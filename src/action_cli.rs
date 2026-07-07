//! `sekaictl action` CLI: manage governed-action policy and approvals (Plan 9).
//!
//! Connects to the sekai control plane (via `CHISEI_GRPC_URL` or `SEKAI_SOCKET`,
//! defaulting to the local UDS) and drives the action-policy and approval RPCs.

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    ActionPolicy, ApproveActionRequest, DenyActionRequest, GetActionPolicyRequest,
    ListActionPoliciesRequest, ListPendingApprovalsRequest, SetActionPolicyRequest,
};
use std::collections::HashMap;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> String {
    [
        "sekaictl action policy set --scope <scope> [--default allow|deny|require_approval]",
        "                           [--action <name>=<decision>]... [--risk <class>=<decision>]...",
        "                           [--max-mutations <n>] [--max-deletes <n>]",
        "sekaictl action policy get --scope <scope>",
        "sekaictl action policy list",
        "sekaictl action approvals list [--status pending|approved|denied|all]",
        "sekaictl action approvals approve --id <approval_id>",
        "sekaictl action approvals deny --id <approval_id> [--reason <text>]",
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

pub async fn run_action_command(args: Vec<String>) -> Result<(), BoxErr> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", usage());
        return Ok(());
    }
    match args[0].as_str() {
        "policy" => run_policy(args.into_iter().skip(1).collect()).await,
        "approvals" => run_approvals(args.into_iter().skip(1).collect()).await,
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

async fn run_approvals(args: Vec<String>) -> Result<(), BoxErr> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", usage());
        return Ok(());
    }
    let channel = connect_sekai(&target()).await?;
    let mut sekai = SekaiServiceClient::new(channel);

    match args[0].as_str() {
        "list" => {
            let status = flag_value(&args[1..], "--status").unwrap_or_default();
            let approvals = sekai
                .list_pending_approvals(ListPendingApprovalsRequest { status })
                .await?
                .into_inner()
                .approvals;
            if approvals.is_empty() {
                println!("no approvals");
            }
            println!("id\tstatus\taction\trisk\ttarget\tactor\twork_unit");
            for a in approvals {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    a.id, a.status, a.action, a.risk_class, a.target_id, a.actor, a.work_unit
                );
            }
        }
        "approve" => {
            let id = flag_value(&args[1..], "--id")
                .ok_or_else(|| std::io::Error::other("--id required"))?;
            let resp = sekai
                .approve_action(ApproveActionRequest { approval_id: id })
                .await?
                .into_inner();
            if let Some(result) = resp.result {
                println!("approved: {} ({})", result.message, result.decision);
            }
        }
        "deny" => {
            let id = flag_value(&args[1..], "--id")
                .ok_or_else(|| std::io::Error::other("--id required"))?;
            let reason = flag_value(&args[1..], "--reason").unwrap_or_default();
            let approval = sekai
                .deny_action(DenyActionRequest {
                    approval_id: id,
                    reason,
                })
                .await?
                .into_inner()
                .approval
                .unwrap_or_default();
            println!("denied: {} ({})", approval.id, approval.outcome);
        }
        other => {
            eprintln!("unknown action approvals command {other:?}");
            println!("{}", usage());
            return Err(std::io::Error::other("unknown action approvals command").into());
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
}
