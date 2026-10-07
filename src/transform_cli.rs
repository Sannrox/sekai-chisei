//! sekaictl admin transform commands (#1287).

use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
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

async fn open_db() -> Result<Arc<RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let config = RuntimeBackendConfig::from_env(&cfg.db_path)?;
    Ok(crate::db::postgres::off_runtime(|| RuntimeBackend::initialize(config))?.database())
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
    db.run_governed_transform(namespace, transform_id, incremental, now_ms)
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
    let db = open_db().await?;
    let bytes = std::fs::read(&config.file)?;
    let transform: GovernedTransform =
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let stored = put_definition(db.as_ref(), transform, Utc::now().timestamp_millis())
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
    let db = open_db().await?;
    let run = run_named(
        db.as_ref(),
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
    let db = open_db().await?;
    let run = get_named(db.as_ref(), &config.run_id).map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&run)?);
    Ok(())
}

struct ListConfig {
    namespace: String,
}

async fn list_ns(config: ListConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let (transforms, runs) =
        list_named(db.as_ref(), &config.namespace).map_err(std::io::Error::other)?;
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
