//! sekaictl admin model-review commands (#1493).

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::chisei::model_review::{
    self, FamilyEnablementRecord, ModelReviewIdentity, ModelReviewRecord, ModelReviewStatus,
};
use crate::chisei::policy::Policy;
use crate::chisei_store::ChiseiStore;
use crate::combined_stores::CombinedStoreLayout;
use crate::config::Config;
use crate::domain::ListFilter;
use crate::ext::*;
use chrono::Utc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin model-review set --namespace <ns> --provider <id> --model <id> [--digest <digest>] --status <disallowed|reviewed|enabled|revoked> --reason <text> [--actor <principal>]\n  sekaictl admin model-review revoke --namespace <ns> --provider <id> --model <id> [--digest <digest>] --reason <text> [--actor <principal>]\n  sekaictl admin model-review list --namespace <ns>\n  sekaictl admin model-review family-set --namespace <ns> [--region <label>] --family <id> --status <disallowed|reviewed|enabled|revoked> --reason <text> [--actor <principal>]\n  sekaictl admin model-review family-revoke --namespace <ns> [--region <label>] --family <id> --reason <text> [--actor <principal>]\n  sekaictl admin model-review family-list --namespace <ns>\n  sekaictl admin model-review backfill"
}

pub async fn run_model_review_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("set") => set(parse_set(&args[1..])?).await,
        Some("revoke") => revoke(parse_model(&args[1..])?).await,
        Some("list") => list(parse_namespace(&args[1..])?).await,
        Some("family-set") => family_set(parse_family_set(&args[1..])?).await,
        Some("family-revoke") => family_revoke(parse_family(&args[1..])?).await,
        Some("family-list") => family_list(parse_namespace(&args[1..])?).await,
        Some("backfill") => backfill().await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

fn open_store() -> Result<ChiseiStore, BoxErr> {
    let cfg = Config::from_env();
    let layout = CombinedStoreLayout::from_env(&cfg.db_path).map_err(std::io::Error::other)?;
    crate::provider_profile::refresh_provider_registry(&registry_state_path(
        layout.registry_anchor_path(),
        &cfg.db_path,
    ))
    .map_err(std::io::Error::other)?;
    Ok(layout.handles().1)
}

fn registry_state_path(anchor: Option<&str>, db_path: &str) -> PathBuf {
    let fallback = crate::combined_stores::registry_db_anchor(db_path);
    crate::provider_profile::provider_registry_state_path(anchor.unwrap_or(&fallback))
}

struct ModelArgs {
    namespace: String,
    provider: String,
    model: String,
    digest: String,
    status: ModelReviewStatus,
    reason: String,
    actor: String,
}

struct FamilyArgs {
    namespace: String,
    region: String,
    family: String,
    status: ModelReviewStatus,
    reason: String,
    actor: String,
}

fn model_record(args: ModelArgs, status: ModelReviewStatus) -> ModelReviewRecord {
    ModelReviewRecord {
        namespace: args.namespace,
        identity: ModelReviewIdentity::new(args.provider, args.model, args.digest),
        status,
        actor: args.actor,
        reason: args.reason,
        updated_at_ms: Utc::now().timestamp_millis(),
    }
}

async fn set(args: ModelArgs) -> Result<(), BoxErr> {
    let db = open_store()?;
    let status = args.status;
    let record = model_review::set_model_review(&db, model_record(args, status))
        .map_err(std::io::Error::other)?;
    println!("{}", record_json(&record));
    Ok(())
}

async fn revoke(mut args: ModelArgs) -> Result<(), BoxErr> {
    let db = open_store()?;
    args.status = ModelReviewStatus::Revoked;
    let record =
        model_review::revoke_model_review(&db, model_record(args, ModelReviewStatus::Revoked))
            .map_err(std::io::Error::other)?;
    println!("{}", record_json(&record));
    Ok(())
}

async fn list(namespace: String) -> Result<(), BoxErr> {
    let db = open_store()?;
    let records =
        model_review::list_model_reviews(&db, &namespace).map_err(std::io::Error::other)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&records.iter().map(record_value).collect::<Vec<_>>())?
    );
    Ok(())
}

async fn family_set(args: FamilyArgs) -> Result<(), BoxErr> {
    let db = open_store()?;
    let record = model_review::set_family_enablement(
        &db,
        FamilyEnablementRecord {
            namespace: args.namespace,
            region_label: args.region,
            family_id: args.family,
            status: args.status,
            actor: args.actor,
            reason: args.reason,
            updated_at_ms: Utc::now().timestamp_millis(),
        },
    )
    .map_err(std::io::Error::other)?;
    println!("{}", family_json(&record));
    Ok(())
}

async fn family_revoke(args: FamilyArgs) -> Result<(), BoxErr> {
    let db = open_store()?;
    let record = model_review::revoke_family_enablement(
        &db,
        FamilyEnablementRecord {
            namespace: args.namespace,
            region_label: args.region,
            family_id: args.family,
            status: ModelReviewStatus::Revoked,
            actor: args.actor,
            reason: args.reason,
            updated_at_ms: Utc::now().timestamp_millis(),
        },
    )
    .map_err(std::io::Error::other)?;
    println!("{}", family_json(&record));
    Ok(())
}

async fn family_list(namespace: String) -> Result<(), BoxErr> {
    let db = open_store()?;
    let records =
        model_review::list_family_enablement(&db, &namespace).map_err(std::io::Error::other)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&records.iter().map(family_value).collect::<Vec<_>>())?
    );
    Ok(())
}

async fn backfill() -> Result<(), BoxErr> {
    let cfg = Config::from_env();
    let store = open_store()?;
    let hosted = model_review::hosted_candidates_for_backfill(
        store
            .runtime()
            .list_all_hosted_routing_profiles()
            .map_err(std::io::Error::other)?,
        &cfg.routing_endpoint_allowlist,
    );
    let families = model_review::family_from_hosted(&hosted);
    let mut routed = model_review::routed_from_hosted(&hosted);
    let mut policies = BTreeMap::new();
    // Leftover `namespace_policy` first; canonical `policy` objects win.
    for kind in ["namespace_policy", "policy"] {
        let objects = store
            .fact_runtime()
            .list_all_objects(&ListFilter {
                kind: Some(kind.into()),
                ..Default::default()
            })
            .map_err(std::io::Error::other)?;
        for object in objects {
            let namespace = model_review::policy_object_namespace(
                &object.namespace,
                &object.external_id,
                &object.name,
            );
            if namespace.is_empty() {
                continue;
            }
            policies.insert(namespace, policy_from_object(&object));
        }
    }
    for (namespace, policy) in policies {
        routed.extend(model_review::routed_from_policy(&namespace, &policy));
    }
    let written = model_review::backfill_enabled_if_empty(
        &store,
        &routed,
        &families,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{{\"backfilled\":{written}}}");
    Ok(())
}

fn policy_from_object(object: &crate::domain::Object) -> Policy {
    let csv = |key: &str| {
        object
            .properties
            .get(key)
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    Policy {
        allowed_runtimes: csv("allowed_runtimes"),
        allowed_models: csv("allowed_models"),
        default_runtime: object
            .properties
            .get("default_runtime")
            .cloned()
            .unwrap_or_default(),
        default_model: object
            .properties
            .get("default_model")
            .cloned()
            .unwrap_or_default(),
        data_class: object
            .properties
            .get("data_class")
            .cloned()
            .unwrap_or_default(),
    }
}

fn record_json(record: &ModelReviewRecord) -> String {
    serde_json::to_string_pretty(&record_value(record)).expect("json")
}

fn family_json(record: &FamilyEnablementRecord) -> String {
    serde_json::to_string_pretty(&family_value(record)).expect("json")
}

fn record_value(record: &ModelReviewRecord) -> serde_json::Value {
    serde_json::json!({
        "namespace": record.namespace,
        "provider": record.identity.provider,
        "model": record.identity.model,
        "artifact_digest": record.identity.artifact_digest,
        "status": record.status.as_str(),
        "actor": record.actor,
        "reason": record.reason,
        "updated_at_ms": record.updated_at_ms,
    })
}

fn family_value(record: &FamilyEnablementRecord) -> serde_json::Value {
    serde_json::json!({
        "namespace": record.namespace,
        "region": record.region_label,
        "family": record.family_id,
        "status": record.status.as_str(),
        "actor": record.actor,
        "reason": record.reason,
        "updated_at_ms": record.updated_at_ms,
    })
}

fn parse_set(args: &[String]) -> Result<ModelArgs, String> {
    let mut parsed = parse_model(args)?;
    parsed.status =
        ModelReviewStatus::parse(&flag(args, "--status")?.ok_or("--status is required")?)?;
    Ok(parsed)
}

fn parse_model(args: &[String]) -> Result<ModelArgs, String> {
    Ok(ModelArgs {
        namespace: flag(args, "--namespace")?.ok_or("--namespace is required")?,
        provider: flag(args, "--provider")?.ok_or("--provider is required")?,
        model: flag(args, "--model")?.ok_or("--model is required")?,
        digest: flag(args, "--digest")?.unwrap_or_default(),
        status: ModelReviewStatus::Revoked,
        reason: flag(args, "--reason")?.ok_or("--reason is required")?,
        actor: flag(args, "--actor")?.unwrap_or_else(|| "operator".into()),
    })
}

fn parse_family_set(args: &[String]) -> Result<FamilyArgs, String> {
    let mut parsed = parse_family(args)?;
    parsed.status =
        ModelReviewStatus::parse(&flag(args, "--status")?.ok_or("--status is required")?)?;
    Ok(parsed)
}

fn parse_family(args: &[String]) -> Result<FamilyArgs, String> {
    Ok(FamilyArgs {
        namespace: flag(args, "--namespace")?.ok_or("--namespace is required")?,
        region: flag(args, "--region")?.unwrap_or_default(),
        family: flag(args, "--family")?.ok_or("--family is required")?,
        status: ModelReviewStatus::Revoked,
        reason: flag(args, "--reason")?.ok_or("--reason is required")?,
        actor: flag(args, "--actor")?.unwrap_or_else(|| "operator".into()),
    })
}

fn parse_namespace(args: &[String]) -> Result<String, String> {
    flag(args, "--namespace")?.ok_or_else(|| "--namespace is required".into())
}

fn flag(args: &[String], name: &str) -> Result<Option<String>, String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args
                .get(i + 1)
                .cloned()
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| format!("{name} requires a value"))
                .map(Some);
        }
        i += 1;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_names_set_revoke_list_and_family() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin model-review set"));
        assert!(usage.contains("revoke"));
        assert!(usage.contains("family-set"));
        assert!(usage.contains("[--region <label>]"));
        assert!(usage.contains("backfill"));
    }

    #[test]
    fn family_commands_default_to_unscoped_region() {
        let args = [
            "--namespace",
            "sales",
            "--family",
            "hosted.acme",
            "--reason",
            "revoke backfill",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let parsed = parse_family(&args).unwrap();
        assert_eq!(parsed.region, "");
        assert_eq!(parsed.family, "hosted.acme");
    }

    #[test]
    fn sqlite_registry_state_is_not_the_database_file() {
        let path = registry_state_path(Some("/data/sekai.db"), "/data/sekai.db");
        assert_ne!(
            path,
            std::path::PathBuf::from("/data/sekai.db"),
            "operator CLI must not parse the SQLite file as registry JSON"
        );
    }
}
