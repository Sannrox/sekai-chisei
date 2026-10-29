//! sekaictl admin retention commands (#1987).
//!
//! Status, dry-run and run share `RuntimeDb::archive_retained_records` and
//! `retention_archive_status`. Both backends implement those methods, so this
//! surface is not SQLite-only.

use crate::combined_stores::CombinedStoreLayout;
use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::retention::{ArchiveRun, ArchiveStatus};
use chrono::Utc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin retention status\n  sekaictl admin retention dry-run\n  sekaictl admin retention run"
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
                )
                .map_err(std::io::Error::other)?,
            )
        }),
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
) -> Result<ArchiveRun, String> {
    crate::db::postgres::off_runtime(|| {
        if !dry_run {
            crate::store_relocate::refuse_mutating_if_generation_mismatch(stores)?;
        }
        db.archive_retained_records(now, dry_run)
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
    println!("{}", status_json(&status));
    Ok(())
}

fn print_run(run: &ArchiveRun) -> Result<(), BoxErr> {
    println!("{}", run_json(run));
    Ok(())
}

fn status_json(status: &ArchiveStatus) -> String {
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
    })
    .to_string()
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
    use crate::sekai::retention::RetentionPolicy;
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
        let json = status_json(&status);
        assert!(json.contains("content_events"), "{json}");
        assert!(json.contains("last_archived_at_ms"), "{json}");
        assert!(
            status
                .last_archived_at_ms
                .iter()
                .any(|(dataset, at)| dataset == "content_events" && *at > 0),
            "{status:?}"
        );
    }

    #[test]
    fn usage_names_status_dry_run_and_run() {
        assert!(usage().contains("sekaictl admin retention status"));
        assert!(usage().contains("dry-run"));
        assert!(usage().contains(" run"));
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
        let err = archive_admitted(&db, &layout, 2 * DAY_MS, false).unwrap_err();
        assert!(err.contains("restamp"), "{err}");
        assert_eq!(db.retention_archive_status().unwrap(), before);
        let dry = archive_admitted(&db, &layout, 2 * DAY_MS, true).unwrap();
        assert!(dry.dry_run);
        assert_eq!(db.retention_archive_status().unwrap(), before);
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
        let run = archive_admitted(layout.sekai_runtime().as_ref(), &layout, 1, false).unwrap();
        assert!(!run.dry_run);
    }
}
