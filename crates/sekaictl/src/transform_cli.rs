//! sekaictl admin transform commands (#1287).

use crate::cli_args::require_value;
use chisei_core::combined_stores::CombinedStoreLayout;
use chisei_core::config::Config;
use chrono::Utc;
use sekai_core::db::runtime_db::RuntimeDb;
use sekai_core::sekai::governed_transform::{GovernedTransform, TransformRun, TransformSchedule};
use sekai_core::sekai::model_version::ModelBinding;
use std::path::PathBuf;
use std::sync::Arc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin transform put --file <json>\n  sekaictl admin transform run --namespace <ns> --transform-id <id> [--incremental]\n  sekaictl admin transform bind-model --namespace <ns> --model-version <id> --transform-id <id> --input <dataset> --output <dataset> --runtime-image <image> [--every-ms <ms>]\n  sekaictl admin transform get --run-id <id>\n  sekaictl admin transform list --namespace <ns>"
}

pub async fn run_transform_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("put") => put(parse_put(&args[1..])?).await,
        Some("run") => run(parse_run(&args[1..])?).await,
        Some("bind-model") => bind_model(parse_bind_model(&args[1..])?).await,
        Some("get") => get_run(parse_get(&args[1..])?).await,
        Some("list") => list_ns(parse_list(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_layout() -> Result<CombinedStoreLayout, BoxErr> {
    let cfg = Config::from_env();
    Ok(sekai_core::db::postgres::off_runtime(|| {
        chisei_core::store_relocate::open_layout_or_fence(&cfg.db_path)
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

/// Puts the batch transform that scores a dataset with a single-table model
/// version (#3076). Refuses a missing version and a model with more than one
/// input table.
pub fn bind_model_version(
    db: &RuntimeDb,
    namespace: &str,
    version_id: &str,
    binding: ModelBinding,
    now_ms: i64,
) -> Result<GovernedTransform, String> {
    let version = db
        .get_model_version(namespace, version_id)?
        .ok_or(sekai_core::sekai::model_version::MODEL_VERSION_NOT_FOUND)?;
    put_definition(db, version.bind(binding)?, now_ms)
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
    let gate = chisei_core::transform_run_admission::quota_gate(runtime);
    let ctx = (!owner.is_empty()).then(|| chisei_core::tenant_context(&owner, "local"));
    let held = if isolated || owner.is_empty() {
        None
    } else if let (Some(limits), Some(context)) = (
        chisei_core::transform_run_admission::configured_limits(quota, &owner)?,
        ctx.as_ref(),
    ) {
        Some(
            chisei_core::transform_run_admission::admit_transform_run(
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
                let usage = chisei_core::transform_run_admission::record_transform_usage(
                    quota, &owner, &run, "local", now_ms,
                );
                if let Some(admission) = held.as_ref()
                    && chisei_core::transform_run_admission::complete_transform_run(
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

struct BindModelConfig {
    namespace: String,
    version_id: String,
    binding: ModelBinding,
}

async fn bind_model(config: BindModelConfig) -> Result<(), BoxErr> {
    let layout = open_layout().await?;
    let stored = bind_model_version(
        layout.sekai_runtime().as_ref(),
        &config.namespace,
        &config.version_id,
        config.binding,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&stored)?);
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

fn parse_bind_model(args: &[String]) -> Result<BindModelConfig, String> {
    let mut values: std::collections::HashMap<&str, String> = Default::default();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--namespace" | "--model-version" | "--transform-id" | "--input" | "--output"
            | "--runtime-image" | "--every-ms" => {
                values.insert(flag, require_value(args, i, flag)?);
                i += 2;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let mut take = |flag: &str| {
        values
            .remove(flag)
            .ok_or_else(|| format!("bind-model requires {flag}"))
    };
    let schedule = match take("--every-ms") {
        Ok(every) => Some(TransformSchedule {
            every_ms: every
                .parse()
                .map_err(|_| "--every-ms takes milliseconds".to_string())?,
        }),
        Err(_) => None,
    };
    Ok(BindModelConfig {
        namespace: take("--namespace")?,
        version_id: take("--model-version")?,
        binding: ModelBinding {
            transform_id: take("--transform-id")?,
            input_dataset_id: take("--input")?,
            output_dataset_id: take("--output")?,
            runtime_image: take("--runtime-image")?,
            schedule,
        },
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
    use chisei_core::chisei::usage_ledger::UsageLedgerSekaiDbExt;
    use sekai_core::db::sekai::SekaiDb;
    use sekai_core::sekai::dataset::{ColumnDef, Dataset};
    use sekai_core::sekai::governed_transform::{CONTRACT_VERSION, TransformStep};
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

    /// A bound model's runs pin its version in their receipts (#3076).
    #[test]
    fn a_bound_model_runs_with_its_version_pinned() {
        use sekai_core::sekai::model_version::{
            AdapterContract, ModelColumn, ModelInput, ModelVersion, ModelVersionRegistration,
        };
        let db = runtime();
        db.create_dataset(&dataset("in")).unwrap();
        db.create_dataset(&dataset("out")).unwrap();
        db.append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
            .unwrap();
        let id = || ModelColumn {
            name: "id".into(),
            col_type: "string".into(),
        };
        let version = ModelVersion::from_run(
            ModelVersionRegistration {
                namespace: "ops".into(),
                model_name: "scorer".into(),
                digest: "sha256:abc".into(),
                adapter_id: "prefix".into(),
                adapter_version: "1".into(),
                registry_locator: "scorer/abc".into(),
                contract: AdapterContract {
                    inputs: vec![ModelInput {
                        name: "features".into(),
                        columns: vec![id()],
                    }],
                    output: vec![id()],
                },
                run_id: "training".into(),
                actor: "trainer".into(),
            },
            "ops",
            "",
            &Default::default(),
            1,
        )
        .unwrap();
        let version_id = db.insert_model_version(&version).unwrap().version_id;
        let binding = parse_bind_model(
            &[
                "--namespace",
                "ops",
                "--model-version",
                &version_id,
                "--transform-id",
                "score",
                "--input",
                "in",
                "--output",
                "out",
                "--runtime-image",
                "model-runner:1",
                "--every-ms",
                "60000",
            ]
            .map(String::from),
        )
        .unwrap();
        assert!(
            bind_model_version(&db, "ops", "missing", binding.binding.clone(), 10)
                .unwrap_err()
                .contains("not found")
        );
        let stored =
            bind_model_version(&db, "ops", &binding.version_id, binding.binding, 10).unwrap();
        assert_eq!(
            stored.schedule,
            Some(TransformSchedule { every_ms: 60_000 })
        );
        let run = run_named(&db, "ops", "score", false, 20).unwrap();
        assert_eq!(run.input_versions.get("model:features"), Some(&version_id));
    }

    #[test]
    fn run_named_admits_the_put_owner() {
        use chisei_core::chisei::budget::PeriodType;
        use chisei_core::chisei::tenant_quota::TenantQuotaLimits;
        use chisei_core::chisei::usage_ledger::UsageUnit;

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
        chisei_core::transform_run_admission::quota_gate(Arc::new(db.clone()))
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
        use chisei_core::chisei::budget::PeriodType;
        use chisei_core::chisei::tenant_quota::TenantQuotaLimits;
        use chisei_core::chisei::usage_ledger::UsageUnit;
        use chisei_core::chisei_store::ChiseiStore;
        use sekai_core::db::store::SekaiStore;

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
        chisei_core::transform_run_admission::quota_gate(chisei.runtime_arc())
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
