//! sekaictl admin retention commands (#1987, #2023).
//!
//! Status, dry-run, run, and policy list/set/delete share `RuntimeDb`
//! retention methods. Both backends implement those methods, so this
//! surface is not SQLite-only.

use crate::combined_stores::CombinedStoreLayout;
use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::retention::{ArchiveRun, ArchiveStatus, RetentionPolicy};
use chrono::Utc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin retention status\n  sekaictl admin retention dry-run\n  sekaictl admin retention run\n  sekaictl admin retention policy list\n  sekaictl admin retention policy set --dataset <audit|llm_calls|task_observations|content_events> --days <n> [--namespace <ns>] [--data-class <class>]\n  sekaictl admin retention policy delete --dataset <audit|llm_calls|task_observations|content_events> [--namespace <ns>] [--data-class <class>]"
}

pub fn run_retention_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("status") if args.len() == 1 => {
            with_layout(|layout| print_status(layout.sekai_runtime().as_ref()))
        }
        Some("dry-run") if args.len() == 1 => {
            with_layout(|layout| print_run(&run(layout.sekai_runtime().as_ref(), true)?))
        }
        Some("run") if args.len() == 1 => with_layout(|layout| {
            print_run(
                &archive_admitted(
                    layout.sekai_runtime().as_ref(),
                    layout,
                    Utc::now().timestamp_millis(),
                    false,
                    false,
                )
                .map_err(std::io::Error::other)?,
            )
        }),
        Some("policy") => run_policy_command(&args[1..]),
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

fn run_policy_command(args: &[String]) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("list") if args.len() == 1 => {
            with_layout(|layout| print_policies(layout.sekai_runtime().as_ref()))
        }
        Some("set") => {
            let mut policy = parse_set(&args[1..]).map_err(std::io::Error::other)?;
            with_layout(|layout| {
                policy.updated = Utc::now().timestamp_millis();
                mutate_admitted(layout, |db| db.set_retention_policy(&policy))?;
                println!("{}", policy_json(&policy, policy.updated));
                Ok(())
            })
        }
        Some("delete") => {
            let key = parse_delete(&args[1..]).map_err(std::io::Error::other)?;
            with_layout(|layout| {
                mutate_admitted(layout, |db| {
                    db.delete_retention_policy(&key.dataset, &key.namespace, &key.data_class)
                })?;
                println!(
                    "{}",
                    serde_json::json!({
                        "dataset": key.dataset,
                        "namespace": key.namespace,
                        "data_class": key.data_class,
                    })
                );
                Ok(())
            })
        }
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

/// Open, use, and drop the layout off the Tokio runtime so the PostgreSQL
/// client is never constructed or destroyed inside `#[tokio::main]`.
fn with_layout<F>(work: F) -> Result<(), BoxErr>
where
    F: FnOnce(&CombinedStoreLayout) -> Result<(), BoxErr>,
{
    let cfg = Config::from_env();
    crate::db::postgres::off_runtime(move || {
        let layout = open_retention_layout(&cfg.db_path).map_err(std::io::Error::other)?;
        work(&layout)
    })
}

/// Combined dest-pair when both stores are configured, including the
/// no-variable `SEKAI_DATA_DIR` default that derives both files. Otherwise
/// the Sekai plane's owned store (`SEKAI_DB_PATH` or `SEKAI_DATABASE_URL`
/// alone). `sekaictl` has no process-plane flag, so data-dir-only stays Combined.
fn open_retention_layout(default_sqlite_path: &str) -> Result<CombinedStoreLayout, String> {
    let sources = crate::combined_stores::CombinedStoreSources::from_env(default_sqlite_path)?;
    if sources.opens_split() {
        crate::store_relocate::open_layout_or_fence(default_sqlite_path)
    } else {
        crate::plane::ProcessPlane::Sekai.open_layout(default_sqlite_path)
    }
}

/// Archive only when the restore fence admits the mutation. `dry_run` skips
/// the fence because it writes nothing.
pub(crate) fn archive_admitted(
    db: &RuntimeDb,
    stores: &CombinedStoreLayout,
    now: i64,
    dry_run: bool,
    skip_if_busy: bool,
) -> Result<ArchiveRun, String> {
    crate::db::postgres::off_runtime(|| {
        if !dry_run {
            crate::store_relocate::refuse_mutating_if_generation_mismatch(stores)?;
        }
        db.archive_retained_records_locked(now, dry_run, skip_if_busy)
    })
}

/// Policy writes go through the same restore fence as `run`.
fn mutate_admitted<T>(
    stores: &CombinedStoreLayout,
    work: impl FnOnce(&RuntimeDb) -> Result<T, String>,
) -> Result<T, BoxErr> {
    crate::store_relocate::refuse_mutating_if_generation_mismatch(stores)
        .and_then(|_| work(stores.sekai_runtime().as_ref()))
        .map_err(std::io::Error::other)
        .map_err(Into::into)
}

#[derive(Debug)]
struct PolicyKey {
    dataset: String,
    namespace: String,
    data_class: String,
}

fn parse_set(args: &[String]) -> Result<RetentionPolicy, String> {
    let mut dataset = None;
    let mut days = None;
    let mut namespace = String::new();
    let mut data_class = String::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("{arg} requires a value"))?;
        match arg.as_str() {
            "--dataset" => dataset = Some(value.clone()),
            "--days" => {
                days = Some(
                    value
                        .parse::<i32>()
                        .map_err(|_| format!("--days must be a positive integer: {value}"))?,
                )
            }
            "--namespace" => namespace = value.clone(),
            "--data-class" => data_class = value.clone(),
            _ => {
                return Err(format!(
                    "unknown retention policy option {arg:?}\n{}",
                    usage()
                ));
            }
        }
    }
    let dataset = dataset.ok_or_else(|| "--dataset is required".to_string())?;
    let retention_days = days.ok_or_else(|| "--days is required".to_string())?;
    let policy = RetentionPolicy {
        dataset,
        namespace,
        data_class,
        retention_days,
        updated: 0,
    };
    crate::sekai::retention::validate_policy(&policy)?;
    Ok(policy)
}

fn parse_delete(args: &[String]) -> Result<PolicyKey, String> {
    let mut dataset = None;
    let mut namespace = String::new();
    let mut data_class = String::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("{arg} requires a value"))?;
        match arg.as_str() {
            "--dataset" => dataset = Some(value.clone()),
            "--namespace" => namespace = value.clone(),
            "--data-class" => data_class = value.clone(),
            _ => {
                return Err(format!(
                    "unknown retention policy option {arg:?}\n{}",
                    usage()
                ));
            }
        }
    }
    let dataset = dataset.ok_or_else(|| "--dataset is required".to_string())?;
    crate::sekai::retention::validate_policy_dataset(&dataset)?;
    Ok(PolicyKey {
        dataset,
        namespace,
        data_class,
    })
}

fn run(db: &RuntimeDb, dry_run: bool) -> Result<ArchiveRun, BoxErr> {
    db.archive_retained_records(Utc::now().timestamp_millis(), dry_run)
        .map_err(std::io::Error::other)
        .map_err(Into::into)
}

fn print_status(db: &RuntimeDb) -> Result<(), BoxErr> {
    let status = db
        .retention_archive_status()
        .map_err(std::io::Error::other)?;
    let policies = db
        .list_retention_policies()
        .map_err(std::io::Error::other)?;
    println!(
        "{}",
        status_json(&status, &policies, Utc::now().timestamp_millis())
    );
    Ok(())
}

fn print_policies(db: &RuntimeDb) -> Result<(), BoxErr> {
    let policies = db
        .list_retention_policies()
        .map_err(std::io::Error::other)?;
    println!(
        "{}",
        serde_json::json!({
            "policies": policies
                .iter()
                .map(|policy| policy_value(policy, Utc::now().timestamp_millis()))
                .collect::<Vec<_>>(),
        })
    );
    Ok(())
}

fn print_run(run: &ArchiveRun) -> Result<(), BoxErr> {
    println!("{}", run_json(run));
    Ok(())
}

fn status_json(status: &ArchiveStatus, policies: &[RetentionPolicy], now: i64) -> String {
    let datasets: Vec<serde_json::Value> = status
        .records
        .iter()
        .map(|(dataset, records)| {
            let last = status
                .last_archived_at_ms
                .iter()
                .find(|(name, _)| name == dataset)
                .map(|(_, at)| serde_json::json!(at));
            serde_json::json!({
                "dataset": dataset,
                "records": records,
                "last_archived_at_ms": last,
            })
        })
        .collect();
    serde_json::json!({
        "batches": status.batches,
        "last_cutoff_ms": status.last_cutoff_ms,
        "datasets": datasets,
        "policies": policies
            .iter()
            .map(|policy| policy_value(policy, now))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

fn policy_json(policy: &RetentionPolicy, now: i64) -> String {
    policy_value(policy, now).to_string()
}

fn policy_value(policy: &RetentionPolicy, now: i64) -> serde_json::Value {
    serde_json::json!({
        "dataset": policy.dataset,
        "namespace": policy.namespace,
        "data_class": policy.data_class,
        "retention_days": policy.retention_days,
        "updated": policy.updated,
        "cutoff_ms": policy.cutoff_ms(now),
    })
}

fn run_json(run: &ArchiveRun) -> String {
    serde_json::json!({
        "dry_run": run.dry_run,
        "batches": run.batches,
        "batch_id": run.batch_id,
        "audit_archived": run.audit_archived,
        "llm_calls_archived": run.llm_calls_archived,
        "task_observations_archived": run.task_observations_archived,
        "task_observations_redacted": run.task_observations_redacted,
        "content_events_archived": run.content_events_archived,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::runtime_backend::{BackendIdentity, RuntimeBackend};
    use crate::sekai::deduplication::{ContentReferenceRequest, ContentScope};
    use std::sync::Arc;

    const DAY_MS: i64 = 86_400_000;

    fn sqlite() -> (RuntimeDb, Arc<SekaiDb>) {
        let inner = Arc::new(SekaiDb::new(":memory:").unwrap());
        (RuntimeDb::Sqlite(inner.clone()), inner)
    }

    fn seed_aged(db: &SekaiDb) {
        db.put_scoped_content(
            &ContentScope {
                namespace: "retention-cli:namespace".into(),
                classification: "confidential".into(),
                encryption_key_id: "key-1".into(),
                residency: "eu".into(),
            },
            &ContentReferenceRequest {
                reference_id: "retention-cli:reference:aged".into(),
                actor: "retention-cli:actor".into(),
                operation_id: "retention-cli:operation".into(),
                causal_identity: "retention-cli:cause:aged".into(),
                idempotency_key: "retention-cli:put:aged".into(),
                retention_until_ms: None,
                retention_hold: false,
                legal_hold: false,
                archived: false,
                receipt_required: false,
                attestation_required: false,
                preserve_tombstone: true,
            },
            b"aged content",
            100,
        )
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: "content_events".into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
    }

    #[test]
    fn dry_run_reports_counts_and_writes_nothing() {
        let (db, inner) = sqlite();
        seed_aged(&inner);
        let before = db.retention_archive_status().unwrap();
        let dry = db.archive_retained_records(2 * DAY_MS, true).unwrap();
        assert!(dry.dry_run);
        assert!(dry.content_events_archived > 0, "{dry:?}");
        assert_eq!(db.retention_archive_status().unwrap(), before);
        let json = run_json(&dry);
        assert!(json.contains("\"dry_run\":true"), "{json}");
        assert!(!json.contains("\"dry_run\":false"), "{json}");
    }

    #[test]
    fn run_archives_and_status_names_the_dataset() {
        let (db, inner) = sqlite();
        seed_aged(&inner);
        let run = db.archive_retained_records(2 * DAY_MS, false).unwrap();
        assert!(!run.dry_run);
        assert!(run.content_events_archived > 0, "{run:?}");
        let status = db.retention_archive_status().unwrap();
        let policies = db.list_retention_policies().unwrap();
        let json = status_json(&status, &policies, 2 * DAY_MS);
        assert!(json.contains("content_events"), "{json}");
        assert!(json.contains("last_archived_at_ms"), "{json}");
        assert!(json.contains("\"retention_days\":1"), "{json}");
        assert!(json.contains(&format!("\"cutoff_ms\":{DAY_MS}")), "{json}");
        assert!(
            status
                .last_archived_at_ms
                .iter()
                .any(|(dataset, at)| dataset == "content_events" && *at > 0),
            "{status:?}"
        );
    }

    #[test]
    fn usage_names_status_dry_run_run_and_policy() {
        assert!(usage().contains("sekaictl admin retention status"));
        assert!(usage().contains("dry-run"));
        assert!(usage().contains(" run"));
        assert!(usage().contains("policy list"));
        assert!(usage().contains("policy set"));
        assert!(usage().contains("policy delete"));
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parse_set_and_delete_use_dataset_vocabulary() {
        let policy = parse_set(&args(&[
            "--dataset",
            "audit",
            "--days",
            "365",
            "--namespace",
            "ops",
            "--data-class",
            "restricted",
        ]))
        .unwrap();
        assert_eq!(policy.dataset, "audit");
        assert_eq!(policy.retention_days, 365);
        assert_eq!(policy.namespace, "ops");
        assert_eq!(policy.data_class, "restricted");
        assert_eq!(policy.cutoff_ms(365 * DAY_MS), 0);
        let err = parse_set(&args(&["--dataset", "audit", "--days", "0"])).unwrap_err();
        assert!(err.contains("retention_days must be positive"), "{err}");
        let err = parse_set(&args(&["--dataset", "objects", "--days", "1"])).unwrap_err();
        assert!(err.contains("dataset must be"), "{err}");
        let err = parse_set(&args(&["--dataset", "audit"])).unwrap_err();
        assert!(err.contains("--days is required"), "{err}");
        let key = parse_delete(&args(&["--dataset", "llm_calls"])).unwrap();
        assert_eq!(key.dataset, "llm_calls");
        assert!(key.namespace.is_empty());
        assert!(
            parse_delete(&args(&["--dataset", "nope"]))
                .unwrap_err()
                .contains("dataset must be")
        );
    }

    #[test]
    fn policy_json_names_cutoff() {
        let policy = RetentionPolicy {
            dataset: "audit".into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 9,
        };
        let json = policy_json(&policy, 2 * DAY_MS);
        assert!(json.contains("\"dataset\":\"audit\""), "{json}");
        assert!(json.contains(&format!("\"cutoff_ms\":{DAY_MS}")), "{json}");
        assert!(json.contains("\"updated\":9"), "{json}");
    }

    #[test]
    fn run_refuses_restore_fence_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let layout = crate::combined_stores::CombinedStoreSources {
            backend: Some(BackendIdentity::Sqlite),
            default_sqlite_path: sekai.to_str().unwrap().into(),
            sekai_sqlite_path: Some(sekai.to_str().unwrap().into()),
            chisei_sqlite_path: Some(chisei.to_str().unwrap().into()),
            postgres_max_connections: 16,
            ..crate::combined_stores::CombinedStoreSources::default()
        }
        .open()
        .unwrap();
        crate::store_relocate::write_runtime_generation(&layout.sekai_runtime(), 9).unwrap();
        let db = layout.sekai_runtime();
        let before = db.retention_archive_status().unwrap();
        let err = archive_admitted(&db, &layout, 2 * DAY_MS, false, false).unwrap_err();
        assert!(err.contains("restamp"), "{err}");
        assert_eq!(db.retention_archive_status().unwrap(), before);
        let dry = archive_admitted(&db, &layout, 2 * DAY_MS, true, false).unwrap();
        assert!(dry.dry_run);
        assert_eq!(db.retention_archive_status().unwrap(), before);
        let policy = RetentionPolicy {
            dataset: "audit".into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        };
        let err = mutate_admitted(&layout, |db| db.set_retention_policy(&policy)).unwrap_err();
        assert!(err.to_string().contains("restamp"), "{err}");
        assert!(db.list_retention_policies().unwrap().is_empty());
    }

    #[test]
    fn admitted_layout_sets_and_deletes_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let backend =
            RuntimeBackend::from_sqlite_with_enterprise_extension(path.to_str().unwrap(), None)
                .unwrap();
        let layout = CombinedStoreLayout::from_backend(backend);
        let policy = RetentionPolicy {
            dataset: "audit".into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 7,
            updated: 1,
        };
        mutate_admitted(&layout, |db| db.set_retention_policy(&policy)).unwrap();
        assert_eq!(
            layout.sekai_runtime().list_retention_policies().unwrap(),
            vec![policy.clone()]
        );
        mutate_admitted(&layout, |db| {
            db.delete_retention_policy(&policy.dataset, &policy.namespace, &policy.data_class)
        })
        .unwrap();
        assert!(
            layout
                .sekai_runtime()
                .list_retention_policies()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn sekai_owned_layout_is_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let backend =
            RuntimeBackend::from_sqlite_with_enterprise_extension(path.to_str().unwrap(), None)
                .unwrap();
        let layout = CombinedStoreLayout::from_backend(backend);
        assert!(
            !crate::combined_stores::CombinedStoreSources {
                backend: Some(BackendIdentity::Sqlite),
                default_sqlite_path: path.to_str().unwrap().into(),
                sekai_sqlite_path: Some(path.to_str().unwrap().into()),
                postgres_max_connections: 16,
                ..crate::combined_stores::CombinedStoreSources::default()
            }
            .opens_split()
        );
        let run =
            archive_admitted(layout.sekai_runtime().as_ref(), &layout, 1, false, false).unwrap();
        assert!(!run.dry_run);
    }
}
