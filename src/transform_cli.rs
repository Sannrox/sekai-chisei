//! sekaictl admin transform commands (#1287).

use crate::combined_stores::CombinedStoreLayout;
use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::governed_transform::{GovernedTransform, TransformRun};
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin transform put --file <json>\n  sekaictl admin transform run --namespace <ns> --transform-id <id> [--incremental]\n  sekaictl admin transform get --run-id <id>\n  sekaictl admin transform list --namespace <ns>"
}

pub async fn run_transform_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("put") => put(parse_put(&args[1..])?).await,
        Some("run") => run(parse_run(&args[1..])?).await,
        Some("get") => get_run(parse_get(&args[1..])?).await,
        Some("list") => list_ns(parse_list(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_layout() -> Result<CombinedStoreLayout, BoxErr> {
    let cfg = Config::from_env();
    Ok(crate::db::postgres::off_runtime(|| {
        crate::store_relocate::open_layout_or_fence(&cfg.db_path)
    })?)
}

pub fn put_definition(
    db: &RuntimeDb,
    transform: GovernedTransform,
    now_ms: i64,
) -> Result<GovernedTransform, String> {
    let prepared = transform.prepare().map_err(|error| error.message())?;
    db.put_governed_transform(&prepared, now_ms)?;
    Ok(prepared)
}

pub fn run_named(
    db: &RuntimeDb,
    namespace: &str,
    transform_id: &str,
    incremental: bool,
    now_ms: i64,
) -> Result<TransformRun, String> {
    run_named_with_quota(db, db, namespace, transform_id, incremental, now_ms)
}

pub fn run_named_with_quota(
    db: &RuntimeDb,
    quota: &RuntimeDb,
    namespace: &str,
    transform_id: &str,
    incremental: bool,
    now_ms: i64,
) -> Result<TransformRun, String> {
    let owner = db
        .transform_quota_owner(namespace, transform_id)?
        .unwrap_or_default();
    let transform = db
        .get_governed_transform(namespace, transform_id)?
        .ok_or_else(|| "governed transform not found".to_string())?;
    let isolated = transform.is_isolated_process();
    let runtime = Arc::new(quota.clone());
    let gate = crate::composition::transform_run_admission::quota_gate(runtime);
    let ctx =
        (!owner.is_empty()).then(|| crate::provider_credentials::tenant_context(&owner, "local"));
    let held = if isolated || owner.is_empty() {
        None
    } else if let (Some(limits), Some(context)) = (
        crate::composition::transform_run_admission::configured_limits(quota, &owner)?,
        ctx.as_ref(),
    ) {
        Some(
            crate::composition::transform_run_admission::admit_transform_run(
                &gate,
                context,
                &limits,
                &format!("transform-run:{namespace}:{transform_id}:{now_ms}"),
                false,
            )
            .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    match db.run_governed_transform_owned(
        namespace,
        transform_id,
        incremental,
        now_ms,
        &owner,
        &transform.definition_digest,
    ) {
        Ok(run) => {
            if !isolated && !owner.is_empty() {
                let usage = crate::composition::transform_run_admission::record_transform_usage(
                    quota, &owner, &run, "local", now_ms,
                );
                if let Some(admission) = held.as_ref()
                    && crate::composition::transform_run_admission::complete_transform_run(
                        &gate, admission,
                    )
                    .is_err()
                    && admission.reserved_concurrency
                {
                    let _ =
                        db.restore_transform_quota_hold(&run.run_id, &admission.tenant_id, true, 0);
                }
                if usage.is_ok() {
                    let _ = db.take_transform_usage_pending(&run.run_id);
                }
            }
            Ok(run)
        }
        Err(error) => {
            if let Some(admission) = held.as_ref()
                && let Err(failed) = gate.abandon(admission)
                && (failed.remaining.reserved_concurrency
                    || failed.remaining.reserved_request
                    || failed.remaining.reserved_tokens > 0)
            {
                let _ = db.restore_abandoned_quota_hold(
                    &failed.remaining.idempotency_key,
                    &failed.remaining.tenant_id,
                    failed.remaining.reserved_concurrency,
                    failed.remaining.reserved_request,
                    failed.remaining.reserved_tokens,
                );
            }
            Err(error)
        }
    }
}

pub fn get_named(db: &RuntimeDb, run_id: &str) -> Result<TransformRun, String> {
    db.get_governed_transform_run(run_id)?
        .ok_or_else(|| "governed transform run not found".into())
}

pub fn list_named(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<(Vec<GovernedTransform>, Vec<TransformRun>), String> {
    Ok((
        db.list_governed_transforms(namespace)?,
        db.list_governed_transform_runs(namespace, 50)?,
    ))
}

struct PutConfig {
    file: PathBuf,
}

async fn put(config: PutConfig) -> Result<(), BoxErr> {
    let layout = open_layout().await?;
    let bytes = std::fs::read(&config.file)?;
    let transform: GovernedTransform =
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let stored = put_definition(
        layout.sekai_runtime().as_ref(),
        transform,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&stored)?);
    Ok(())
}

struct RunConfig {
    namespace: String,
    transform_id: String,
    incremental: bool,
}

async fn run(config: RunConfig) -> Result<(), BoxErr> {
    let layout = open_layout().await?;
    let run = run_named_with_quota(
        layout.sekai_runtime().as_ref(),
        layout.chisei_runtime().as_ref(),
        &config.namespace,
        &config.transform_id,
        config.incremental,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&run)?);
    Ok(())
}

struct GetConfig {
    run_id: String,
}

async fn get_run(config: GetConfig) -> Result<(), BoxErr> {
    let layout = open_layout().await?;
    let run = get_named(layout.sekai_runtime().as_ref(), &config.run_id)
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&run)?);
    Ok(())
}

struct ListConfig {
    namespace: String,
}

async fn list_ns(config: ListConfig) -> Result<(), BoxErr> {
    let layout = open_layout().await?;
    let (transforms, runs) = list_named(layout.sekai_runtime().as_ref(), &config.namespace)
        .map_err(std::io::Error::other)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "transforms": transforms,
            "runs": runs,
        }))?
    );
    Ok(())
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_put(args: &[String]) -> Result<PutConfig, String> {
    let mut file = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                file = Some(PathBuf::from(require_value(args, i, "--file")?));
                i += 2;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(PutConfig {
        file: file.ok_or_else(|| "put requires --file".to_string())?,
    })
}

fn parse_run(args: &[String]) -> Result<RunConfig, String> {
    let mut namespace = None;
    let mut transform_id = None;
    let mut incremental = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--transform-id" => {
                transform_id = Some(require_value(args, i, "--transform-id")?);
                i += 2;
            }
            "--incremental" => {
                incremental = true;
                i += 1;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(RunConfig {
        namespace: namespace.ok_or_else(|| "run requires --namespace".to_string())?,
        transform_id: transform_id.ok_or_else(|| "run requires --transform-id".to_string())?,
        incremental,
    })
}

fn parse_get(args: &[String]) -> Result<GetConfig, String> {
    let mut run_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--run-id" => {
                run_id = Some(require_value(args, i, "--run-id")?);
                i += 2;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(GetConfig {
        run_id: run_id.ok_or_else(|| "get requires --run-id".to_string())?,
    })
}

fn parse_list(args: &[String]) -> Result<ListConfig, String> {
    let mut namespace = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(ListConfig {
        namespace: namespace.ok_or_else(|| "list requires --namespace".to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, TransformStep};
    use std::collections::HashMap;

    fn runtime() -> RuntimeDb {
        RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    fn dataset(id: &str) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: vec![ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    #[test]
    fn dry_path_put_run_get_lists_receipt() {
        let db = runtime();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
            .unwrap();
        let stored = put_definition(
            &db,
            GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t1".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    column: String::new(),
                    op: String::new(),
                    value: String::new(),
                    columns: vec!["id".into()],
                }],
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: None,
                schedule: None,
                trigger: None,
            },
            10,
        )
        .unwrap();
        assert!(stored.definition_digest.starts_with("sha256:"));
        let run = run_named(&db, "ops", "t1", false, 20).unwrap();
        assert!(!run.quarantined);
        assert_eq!(run.rows_in, 1);
        let fetched = get_named(&db, &run.run_id).unwrap();
        assert_eq!(fetched.run_id, run.run_id);
        let (transforms, runs) = list_named(&db, "ops").unwrap();
        assert_eq!(transforms.len(), 1);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run.run_id);
    }

    #[test]
    fn run_named_admits_the_put_owner() {
        use crate::chisei::budget::PeriodType;
        use crate::chisei::tenant_quota::TenantQuotaLimits;
        use crate::chisei::usage_ledger::UsageUnit;

        let db = runtime();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
            .unwrap();
        db.put_governed_transform_owned(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t1".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    column: String::new(),
                    op: String::new(),
                    value: String::new(),
                    columns: vec!["id".into()],
                }],
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: None,
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
            "tenant-a",
        )
        .unwrap();
        crate::composition::transform_run_admission::quota_gate(Arc::new(db.clone()))
            .configure(
                "tenant-a",
                &TenantQuotaLimits {
                    version: 1,
                    max_requests_per_period: Some(1),
                    max_tokens_per_period: None,
                    max_concurrency: None,
                    max_storage_bytes: None,
                    period: PeriodType::Daily,
                },
            )
            .unwrap();
        run_named(&db, "ops", "t1", false, 20).unwrap();
        let RuntimeDb::Sqlite(sqlite) = &db else {
            panic!("sqlite");
        };
        let usage = sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap();
        assert_eq!(usage.measured, 1);
        let denied = run_named(&db, "ops", "t1", false, 30).unwrap_err();
        assert!(denied.contains("exhausted") || denied.contains("requests"));
    }

    #[test]
    fn run_named_split_plane_admits_on_the_chisei_dest() {
        use crate::chisei::budget::PeriodType;
        use crate::chisei::tenant_quota::TenantQuotaLimits;
        use crate::chisei::usage_ledger::UsageUnit;
        use crate::chisei_store::ChiseiStore;
        use crate::db::store::SekaiStore;

        let dir = tempfile::tempdir().unwrap();
        let sekai = SekaiStore::open_sqlite(dir.path().join("sekai.db").to_str().unwrap());
        let chisei = ChiseiStore::open_sqlite(dir.path().join("chisei.db").to_str().unwrap());
        let db = sekai.runtime();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
            .unwrap();
        db.put_governed_transform_owned(
            &GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: "ops".into(),
                transform_id: "t-split".into(),
                input_dataset_id: "in".into(),
                output_dataset_id: "out".into(),
                steps: vec![TransformStep {
                    kind: "project".into(),
                    column: String::new(),
                    op: String::new(),
                    value: String::new(),
                    columns: vec!["id".into()],
                }],
                quality_rule: String::new(),
                definition_digest: String::new(),
                analytical: None,
                isolated_process: None,
                schedule: None,
                trigger: None,
            }
            .prepare()
            .unwrap(),
            10,
            "tenant-a",
        )
        .unwrap();
        crate::composition::transform_run_admission::quota_gate(chisei.runtime_arc())
            .configure(
                "tenant-a",
                &TenantQuotaLimits {
                    version: 1,
                    max_requests_per_period: Some(1),
                    max_tokens_per_period: None,
                    max_concurrency: None,
                    max_storage_bytes: None,
                    period: PeriodType::Daily,
                },
            )
            .unwrap();
        run_named_with_quota(db, chisei.runtime(), "ops", "t-split", false, 20).unwrap();
        let RuntimeDb::Sqlite(chisei_sqlite) = chisei.runtime() else {
            panic!("sqlite");
        };
        let usage = chisei_sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap();
        assert_eq!(usage.measured, 1);
        let RuntimeDb::Sqlite(sekai_sqlite) = db else {
            panic!("sqlite");
        };
        assert!(
            sekai_sqlite
                .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
                .is_err()
        );
    }

    #[test]
    fn parse_run_accepts_incremental() {
        let parsed = parse_run(&[
            "--namespace".into(),
            "ops".into(),
            "--transform-id".into(),
            "t1".into(),
            "--incremental".into(),
        ])
        .unwrap();
        assert!(parsed.incremental);
        assert_eq!(parsed.namespace, "ops");
    }
}
