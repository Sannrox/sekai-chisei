//! `sekaictl admin governance action` CLI: manage governed-action policy
//! and the governed-action type registry.
//!
//! Connects to the sekai control plane (via `CHISEI_GRPC_URL` or `SEKAI_SOCKET`,
//! defaulting to the local UDS) and drives the action-policy and type RPCs.

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    ActionPolicy, GetActionPolicyRequest, GetGovernedActionTypeRequest, GovernedActionType,
    ListActionPoliciesRequest, ListGovernedActionTypesRequest, PutGovernedActionTypeRequest,
    SetActionPolicyRequest,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> String {
    [
        "sekaictl admin governance action policy set --scope <scope> [--default allow|deny|require_approval]",
        "                           [--action <name>=<decision>]... [--risk <class>=<decision>]...",
        "                           [--max-mutations <n>] [--max-deletes <n>]",
        "sekaictl admin governance action policy get --scope <scope>",
        "sekaictl admin governance action policy list",
        "sekaictl admin governance action type put --file <type.json|-> [--request-id <id>]",
        "sekaictl admin governance action type get --namespace <ns> --type-id <id> --version <ver>",
        "sekaictl admin governance action type list [--namespace <ns>] [--type-id <id>] [--enabled-only]",
    ]
    .join("\n")
}

fn target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".to_string())
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn multi_flag(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if arg == flag
            && let Some(value) = args.get(i + 1)
        {
            out.push(value.clone());
        }
    }
    out
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn parse_pairs(raw: &[String]) -> Result<HashMap<String, String>, BoxErr> {
    let mut map = HashMap::new();
    for token in raw {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| std::io::Error::other(format!("expected key=value, got {token:?}")))?;
        map.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(map)
}

#[derive(Debug, Deserialize)]
struct TypeFile {
    namespace: String,
    type_id: String,
    version: String,
    #[serde(default)]
    description: String,
    parameter_schema_json: Value,
    #[serde(default)]
    allowed_effect_kinds: Vec<String>,
    #[serde(default)]
    policy_scope: String,
    #[serde(default)]
    budget_scope: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    request_id: String,
}

fn default_enabled() -> bool {
    true
}

fn schema_json(value: &Value) -> Result<String, BoxErr> {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(std::io::Error::other("parameter_schema_json is required").into());
            }
            serde_json::from_str::<Value>(trimmed).map_err(|error| {
                std::io::Error::other(format!("parameter_schema_json: {error}"))
            })?;
            Ok(trimmed.to_string())
        }
        Value::Object(_) => Ok(serde_json::to_string(value)?),
        _ => Err(std::io::Error::other(
            "parameter_schema_json must be a JSON object or a JSON object string",
        )
        .into()),
    }
}

fn load_type_file(path: &str) -> Result<TypeFile, BoxErr> {
    let raw = if path == "-" {
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        std::fs::read_to_string(Path::new(path))?
    };
    let parsed: TypeFile = serde_json::from_str(raw.trim()).map_err(|error| {
        std::io::Error::other(format!("governed action type file {path}: {error}"))
    })?;
    if parsed.namespace.trim().is_empty()
        || parsed.type_id.trim().is_empty()
        || parsed.version.trim().is_empty()
    {
        return Err(std::io::Error::other("namespace, type_id, and version are required").into());
    }
    Ok(parsed)
}

fn type_from_file(parsed: TypeFile) -> Result<(GovernedActionType, String), BoxErr> {
    let request_id = if parsed.request_id.trim().is_empty() {
        format!(
            "put-{}-{}-{}",
            parsed.namespace.trim(),
            parsed.type_id.trim(),
            parsed.version.trim()
        )
    } else {
        parsed.request_id.trim().to_string()
    };
    Ok((
        GovernedActionType {
            namespace: parsed.namespace.trim().to_string(),
            type_id: parsed.type_id.trim().to_string(),
            version: parsed.version.trim().to_string(),
            description: parsed.description,
            parameter_schema_json: schema_json(&parsed.parameter_schema_json)?,
            allowed_effect_kinds: parsed.allowed_effect_kinds,
            policy_scope: parsed.policy_scope,
            budget_scope: parsed.budget_scope,
            enabled: parsed.enabled,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        },
        request_id,
    ))
}

fn print_type(type_def: &GovernedActionType) {
    let mut effects = type_def.allowed_effect_kinds.clone();
    effects.sort();
    println!(
        "{}/{}@{} enabled={} effects={}",
        type_def.namespace,
        type_def.type_id,
        type_def.version,
        type_def.enabled,
        if effects.is_empty() {
            "-".to_string()
        } else {
            effects.join(",")
        }
    );
}

pub async fn run_action_command(args: Vec<String>) -> Result<(), BoxErr> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", usage());
        return Ok(());
    }
    match args[0].as_str() {
        "policy" => run_policy(args.into_iter().skip(1).collect()).await,
        "type" => run_type(args.into_iter().skip(1).collect()).await,
        other => {
            eprintln!("unknown action command {other:?}");
            println!("{}", usage());
            Err(std::io::Error::other("unknown action command").into())
        }
    }
}

fn print_policy(policy: &ActionPolicy) {
    println!("scope: {}", policy.scope);
    println!("default_decision: {}", policy.default_decision);
    if !policy.action_overrides.is_empty() {
        let mut pairs: Vec<_> = policy
            .action_overrides
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        pairs.sort();
        println!("action_overrides: {}", pairs.join(", "));
    }
    if !policy.risk_overrides.is_empty() {
        let mut pairs: Vec<_> = policy
            .risk_overrides
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        pairs.sort();
        println!("risk_overrides: {}", pairs.join(", "));
    }
    if policy.max_mutations_per_work_unit > 0 {
        println!(
            "max_mutations_per_work_unit: {}",
            policy.max_mutations_per_work_unit
        );
    }
    if policy.max_deletes_per_work_unit > 0 {
        println!(
            "max_deletes_per_work_unit: {}",
            policy.max_deletes_per_work_unit
        );
    }
}

async fn run_policy(args: Vec<String>) -> Result<(), BoxErr> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", usage());
        return Ok(());
    }
    let channel = connect_sekai(&target()).await?;
    let mut sekai = SekaiServiceClient::new(channel);

    match args[0].as_str() {
        "set" => {
            let rest = &args[1..];
            let scope = flag_value(rest, "--scope")
                .ok_or_else(|| std::io::Error::other("--scope required"))?;
            let default_decision =
                flag_value(rest, "--default").unwrap_or_else(|| "allow".to_string());
            let action_overrides = parse_pairs(&multi_flag(rest, "--action"))?;
            let risk_overrides = parse_pairs(&multi_flag(rest, "--risk"))?;
            let max_mutations = flag_value(rest, "--max-mutations")
                .map(|v| v.parse::<u32>())
                .transpose()?
                .unwrap_or(0);
            let max_deletes = flag_value(rest, "--max-deletes")
                .map(|v| v.parse::<u32>())
                .transpose()?
                .unwrap_or(0);
            let policy = ActionPolicy {
                scope,
                default_decision,
                action_overrides,
                risk_overrides,
                max_mutations_per_work_unit: max_mutations,
                max_deletes_per_work_unit: max_deletes,
            };
            let stored = sekai
                .set_action_policy(SetActionPolicyRequest {
                    policy: Some(policy),
                })
                .await?
                .into_inner()
                .policy
                .unwrap_or_default();
            print_policy(&stored);
        }
        "get" => {
            let scope = flag_value(&args[1..], "--scope")
                .ok_or_else(|| std::io::Error::other("--scope required"))?;
            match sekai
                .get_action_policy(GetActionPolicyRequest {
                    scope: scope.clone(),
                })
                .await?
                .into_inner()
                .policy
            {
                Some(policy) => print_policy(&policy),
                None => println!("no action policy for scope {scope}"),
            }
        }
        "list" => {
            let policies = sekai
                .list_action_policies(ListActionPoliciesRequest {})
                .await?
                .into_inner()
                .policies;
            if policies.is_empty() {
                println!("no action policies");
            }
            for policy in policies {
                print_policy(&policy);
                println!("---");
            }
        }
        other => {
            eprintln!("unknown action policy command {other:?}");
            println!("{}", usage());
            return Err(std::io::Error::other("unknown action policy command").into());
        }
    }
    Ok(())
}

async fn run_type(args: Vec<String>) -> Result<(), BoxErr> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", usage());
        return Ok(());
    }
    let channel = connect_sekai(&target()).await?;
    let mut sekai = SekaiServiceClient::new(channel);

    match args[0].as_str() {
        "put" => {
            let rest = &args[1..];
            let path = flag_value(rest, "--file")
                .ok_or_else(|| std::io::Error::other("--file required"))?;
            let parsed = load_type_file(&path)?;
            let (type_def, default_request_id) = type_from_file(parsed)?;
            let request_id = flag_value(rest, "--request-id").unwrap_or(default_request_id);
            let stored = sekai
                .put_governed_action_type(PutGovernedActionTypeRequest {
                    r#type: Some(type_def),
                    request_id,
                })
                .await?
                .into_inner()
                .r#type
                .ok_or_else(|| std::io::Error::other("PutGovernedActionType returned no type"))?;
            print_type(&stored);
        }
        "get" => {
            let rest = &args[1..];
            let namespace = flag_value(rest, "--namespace")
                .ok_or_else(|| std::io::Error::other("--namespace required"))?;
            let type_id = flag_value(rest, "--type-id")
                .ok_or_else(|| std::io::Error::other("--type-id required"))?;
            let version = flag_value(rest, "--version")
                .ok_or_else(|| std::io::Error::other("--version required"))?;
            match sekai
                .get_governed_action_type(GetGovernedActionTypeRequest {
                    namespace,
                    type_id,
                    version,
                })
                .await?
                .into_inner()
                .r#type
            {
                Some(type_def) => print_type(&type_def),
                None => println!("governed action type not found"),
            }
        }
        "list" => {
            let rest = &args[1..];
            let types = sekai
                .list_governed_action_types(ListGovernedActionTypesRequest {
                    namespace: flag_value(rest, "--namespace").unwrap_or_default(),
                    type_id: flag_value(rest, "--type-id").unwrap_or_default(),
                    enabled_only: has_flag(rest, "--enabled-only"),
                })
                .await?
                .into_inner()
                .types;
            if types.is_empty() {
                println!("no governed action types");
            }
            for type_def in types {
                print_type(&type_def);
            }
        }
        other => {
            eprintln!("unknown action type command {other:?}");
            println!("{}", usage());
            return Err(std::io::Error::other("unknown action type command").into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pairs_splits_key_value() {
        let pairs =
            parse_pairs(&["delete_link=deny".to_string(), "rotate=allow".to_string()]).unwrap();
        assert_eq!(pairs["delete_link"], "deny");
        assert_eq!(pairs["rotate"], "allow");
        assert!(parse_pairs(&["bad".to_string()]).is_err());
    }

    #[test]
    fn multi_flag_collects_all_values() {
        let args = vec![
            "--action".to_string(),
            "a=deny".to_string(),
            "--action".to_string(),
            "b=allow".to_string(),
        ];
        assert_eq!(multi_flag(&args, "--action"), vec!["a=deny", "b=allow"]);
    }

    #[test]
    fn flag_value_reads_single() {
        let args = vec!["--scope".to_string(), "agent:x".to_string()];
        assert_eq!(flag_value(&args, "--scope"), Some("agent:x".to_string()));
        assert_eq!(flag_value(&args, "--missing"), None);
    }

    #[test]
    fn type_file_accepts_object_schema() {
        let parsed: TypeFile = serde_json::from_str(
            r#"{
              "namespace": "workshop",
              "type_id": "customer-product-definition.propose",
              "version": "v1",
              "parameter_schema_json": {
                "type": "object",
                "additionalProperties": false,
                "required": ["definition_digest"],
                "properties": {"definition_digest": {"type": "string"}}
              },
              "allowed_effect_kinds": ["notify"]
            }"#,
        )
        .unwrap();
        let (type_def, request_id) = type_from_file(parsed).unwrap();
        assert_eq!(type_def.namespace, "workshop");
        assert_eq!(type_def.type_id, "customer-product-definition.propose");
        assert_eq!(type_def.version, "v1");
        assert!(type_def.enabled);
        assert_eq!(type_def.allowed_effect_kinds, vec!["notify"]);
        assert!(type_def.parameter_schema_json.contains("definition_digest"));
        assert!(!type_def.parameter_schema_json.contains('\n'));
        assert_eq!(
            request_id,
            "put-workshop-customer-product-definition.propose-v1"
        );
    }

    #[test]
    fn type_file_accepts_string_schema() {
        let parsed: TypeFile = serde_json::from_str(
            r#"{
              "namespace": "workshop",
              "type_id": "customer-product-definition.propose",
              "version": "v1",
              "parameter_schema_json": "{\"type\":\"object\",\"properties\":{},\"required\":[],\"additionalProperties\":false}",
              "allowed_effect_kinds": ["notify"],
              "enabled": false,
              "request_id": "seed-1"
            }"#,
        )
        .unwrap();
        let (type_def, request_id) = type_from_file(parsed).unwrap();
        assert!(!type_def.enabled);
        assert_eq!(request_id, "seed-1");
        assert_eq!(
            type_def.parameter_schema_json,
            r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#
        );
    }
}
