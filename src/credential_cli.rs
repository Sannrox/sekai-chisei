use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    CreateCredentialRequest, CredentialRecord, ListCredentialsRequest, RevokeCredentialRequest,
    RotateCredentialRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialCommand {
    Create { principal: String },
    Rotate { principal: String },
    Revoke { principal: String },
    BulkCreate { principals: Vec<String> },
    BulkRotate { principals: Vec<String> },
    BulkRevoke { principals: Vec<String> },
    List,
}

pub fn usage() -> &'static str {
    concat!(
        "Usage: sekaictl admin access credential create <principal>\n",
        "       sekaictl admin access credential rotate <principal>\n",
        "       sekaictl admin access credential revoke <principal>\n",
        "       sekaictl admin access credential bulk create <principal...>\n",
        "       sekaictl admin access credential bulk rotate <principal...>\n",
        "       sekaictl admin access credential bulk revoke <principal...>\n",
        "       sekaictl admin access credential list"
    )
}

pub fn parse_credential_command<I>(args: I) -> Result<CredentialCommand, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let command = args.next().ok_or_else(|| usage().to_string())?;

    match command.as_str() {
        "create" => {
            let principal = args
                .next()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "credential create requires <principal>".to_string())?;
            ensure_no_more_args(args)?;
            validate_principal(&principal)?;
            Ok(CredentialCommand::Create { principal })
        }
        "rotate" => {
            let principal = args
                .next()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "credential rotate requires <principal>".to_string())?;
            ensure_no_more_args(args)?;
            validate_principal(&principal)?;
            Ok(CredentialCommand::Rotate { principal })
        }
        "revoke" => {
            let principal = args
                .next()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "credential revoke requires <principal>".to_string())?;
            ensure_no_more_args(args)?;
            validate_principal(&principal)?;
            Ok(CredentialCommand::Revoke { principal })
        }
        "bulk" => {
            let action = args
                .next()
                .ok_or_else(|| "credential bulk requires create|rotate|revoke".to_string())?;
            let principals = parse_principal_list(args)?;
            match action.as_str() {
                "create" => Ok(CredentialCommand::BulkCreate { principals }),
                "rotate" => Ok(CredentialCommand::BulkRotate { principals }),
                "revoke" => Ok(CredentialCommand::BulkRevoke { principals }),
                _ => Err(format!(
                    "credential bulk requires create|rotate|revoke, got {action:?}"
                )),
            }
        }
        "list" => {
            ensure_no_more_args(args)?;
            Ok(CredentialCommand::List)
        }
        other => Err(format!("unknown credential command {other:?}")),
    }
}

fn ensure_no_more_args<I>(mut args: I) -> Result<(), String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .map(|_| "unexpected trailing arguments".to_string())
        .map_or(Ok(()), Err)
}

fn parse_principal_list<I>(args: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = String>,
{
    let mut principals = Vec::new();
    for principal in args {
        let principal = principal.trim().to_string();
        if principal.is_empty() {
            return Err("principal must not be empty".to_string());
        }
        validate_principal(&principal)?;
        principals.push(principal);
    }
    if principals.is_empty() {
        return Err("credential bulk requires at least one principal".to_string());
    }
    Ok(principals)
}

fn validate_principal(principal: &str) -> Result<(), String> {
    if principal.is_empty() {
        return Err("principal must not be empty".to_string());
    }

    if !principal
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
    {
        return Err("principal must match [a-zA-Z0-9._-]+".to_string());
    }
    Ok(())
}

fn credential_target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".to_string())
}

pub async fn create_credential(principal: &str) -> Result<String, String> {
    validate_principal(principal)?;
    let channel = connect_sekai(&credential_target())
        .await
        .map_err(|error| format!("connect to control plane: {error}"))?;
    let response = SekaiServiceClient::new(channel)
        .create_credential(CreateCredentialRequest {
            principal: principal.to_string(),
            managed_team_principal: false,
            tenant_id: String::new(),
        })
        .await
        .map_err(|error| format!("create credential: {error}"))?;
    Ok(response.into_inner().token)
}

pub async fn rotate_credential(principal: &str) -> Result<String, String> {
    validate_principal(principal)?;
    let channel = connect_sekai(&credential_target())
        .await
        .map_err(|error| format!("connect to control plane: {error}"))?;
    let response = SekaiServiceClient::new(channel)
        .rotate_credential(RotateCredentialRequest {
            principal: principal.to_string(),
            managed_team_principal: false,
            tenant_id: String::new(),
        })
        .await
        .map_err(|error| format!("rotate credential: {error}"))?;
    Ok(response.into_inner().token)
}

pub async fn revoke_credential(principal: &str) -> Result<CredentialRecord, String> {
    validate_principal(principal)?;
    let channel = connect_sekai(&credential_target())
        .await
        .map_err(|error| format!("connect to control plane: {error}"))?;
    SekaiServiceClient::new(channel)
        .revoke_credential(RevokeCredentialRequest {
            principal: principal.to_string(),
            tenant_id: String::new(),
        })
        .await
        .map_err(|error| format!("revoke credential: {error}"))?
        .into_inner()
        .credential
        .ok_or_else(|| "control plane returned no revoked credential".to_string())
}

pub async fn list_credentials() -> Result<Vec<CredentialRecord>, String> {
    let channel = connect_sekai(&credential_target())
        .await
        .map_err(|error| format!("connect to control plane: {error}"))?;
    Ok(SekaiServiceClient::new(channel)
        .list_credentials(ListCredentialsRequest {
            tenant_id: String::new(),
        })
        .await
        .map_err(|error| format!("list credentials: {error}"))?
        .into_inner()
        .credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_create() {
        let command =
            parse_credential_command(["create".to_string(), "agent-a".to_string()]).unwrap();
        assert_eq!(
            command,
            CredentialCommand::Create {
                principal: "agent-a".to_string()
            }
        );
    }

    #[test]
    fn parse_rotate_and_revoke() {
        assert_eq!(
            parse_credential_command(["rotate".to_string(), "agent-a".to_string()]).unwrap(),
            CredentialCommand::Rotate {
                principal: "agent-a".to_string()
            }
        );
        assert_eq!(
            parse_credential_command(["revoke".to_string(), "agent-a".to_string()]).unwrap(),
            CredentialCommand::Revoke {
                principal: "agent-a".to_string()
            }
        );
    }

    #[test]
    fn reject_invalid_principal() {
        let err =
            parse_credential_command(["create".to_string(), "agent a".to_string()]).unwrap_err();
        assert_eq!(err, "principal must match [a-zA-Z0-9._-]+");
    }

    #[test]
    fn parse_list() {
        assert_eq!(
            parse_credential_command(["list".to_string()]).unwrap(),
            CredentialCommand::List
        );
    }

    #[test]
    fn parse_bulk_create_rotate_revoke() {
        assert_eq!(
            parse_credential_command([
                "bulk".to_string(),
                "create".to_string(),
                "agent-a".to_string(),
                "agent-b".to_string(),
            ])
            .unwrap(),
            CredentialCommand::BulkCreate {
                principals: vec!["agent-a".to_string(), "agent-b".to_string()]
            }
        );
        assert_eq!(
            parse_credential_command([
                "bulk".to_string(),
                "rotate".to_string(),
                "agent-a".to_string(),
            ])
            .unwrap(),
            CredentialCommand::BulkRotate {
                principals: vec!["agent-a".to_string()]
            }
        );
        assert_eq!(
            parse_credential_command([
                "bulk".to_string(),
                "revoke".to_string(),
                "agent-a".to_string()
            ])
            .unwrap(),
            CredentialCommand::BulkRevoke {
                principals: vec!["agent-a".to_string()]
            }
        );
    }
}
