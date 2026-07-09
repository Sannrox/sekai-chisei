use chrono::Utc;
use uuid::Uuid;

use crate::config::Config;
use crate::db::sekai::{PrincipalCredential, SekaiDb};
use crate::gateway_keys::hash_gateway_key;

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
        "Usage: sekaictl credential create <principal>\n",
        "       sekaictl credential rotate <principal>\n",
        "       sekaictl credential revoke <principal>\n",
        "       sekaictl credential bulk create <principal...>\n",
        "       sekaictl credential bulk rotate <principal...>\n",
        "       sekaictl credential bulk revoke <principal...>\n",
        "       sekaictl credential list"
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

fn credential_db_path() -> String {
    Config::from_env().db_path
}

pub fn create_credential(principal: &str) -> Result<String, String> {
    validate_principal(principal)?;
    let db = SekaiDb::new(&credential_db_path()).map_err(|err| format!("open db: {err}"))?;

    if !db
        .list_credentials(Some(principal), Some("active"))?
        .is_empty()
    {
        return Err(format!(
            "active credential already exists for {principal:?}; run rotate instead"
        ));
    }

    let token = format!(
        "sekai_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    db.create_principal_credential(
        principal,
        &hash_gateway_key(&token),
        Utc::now().timestamp_millis(),
    )
    .map_err(|err| format!("create credential: {err}"))?;
    Ok(token)
}

pub fn rotate_credential(principal: &str) -> Result<String, String> {
    validate_principal(principal)?;
    let db = SekaiDb::new(&credential_db_path()).map_err(|err| format!("open db: {err}"))?;

    if db
        .list_credentials(Some(principal), Some("active"))?
        .is_empty()
    {
        return Err(format!("no active credential for {principal:?}"));
    }

    let token = format!(
        "sekai_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    db.rotate_principal_credential(principal, &hash_gateway_key(&token))
        .map_err(|err| format!("rotate credential: {err}"))?;
    Ok(token)
}

pub fn revoke_credential(principal: &str) -> Result<PrincipalCredential, String> {
    validate_principal(principal)?;
    let db = SekaiDb::new(&credential_db_path()).map_err(|err| format!("open db: {err}"))?;
    db.revoke_principal_credential(principal)
        .map_err(|err| format!("revoke credential: {err}"))?
        .ok_or_else(|| format!("no active credential for {principal:?}"))
}

pub fn list_credentials() -> Result<Vec<PrincipalCredential>, String> {
    let db = SekaiDb::new(&credential_db_path()).map_err(|err| format!("open db: {err}"))?;
    db.list_credentials(None, None)
        .map_err(|err| format!("list credentials: {err}"))
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
