//! Dual-backend community-store dispatch for retention.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_retention_policy(policy),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.set_retention_policy(policy))
            }
        }
    }

    pub fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_retention_policies(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_retention_policies()),
        }
    }

    pub fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String> {
        match self {
            Self::Sqlite(db) => db.erase_subject(request),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.erase_subject(request)),
        }
    }

    /// The retention entry point (ADR 0141): move records past their policy
    /// cutoff into the in-database archive and remove or redact them in the
    /// hot tables, one transaction per batch. Idempotent and safe to run on
    /// several replicas at once. `dry_run` reports the counts and writes
    /// nothing. The plane tick and `sekaictl admin retention` call this.
    pub fn archive_retained_records(&self, now: i64, dry_run: bool) -> Result<ArchiveRun, String> {
        match self {
            Self::Sqlite(db) => db.archive_retained_records(now, dry_run),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.archive_retained_records(now, dry_run))
            }
        }
    }

    /// Verify the in-database retention archive.
    pub fn verify_retention_archive(&self) -> Result<ArchiveVerification, String> {
        match self {
            Self::Sqlite(db) => db.verify_retention_archive(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.verify_retention_archive())
            }
        }
    }

    /// What the in-database retention archive holds.
    pub fn retention_archive_status(
        &self,
    ) -> Result<crate::sekai::retention::ArchiveStatus, String> {
        match self {
            Self::Sqlite(db) => db.retention_archive_status(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.retention_archive_status())
            }
        }
    }

    pub fn run_retention(&self, now: i64) -> Result<RetentionRun, String> {
        match self {
            Self::Sqlite(db) => db.run_retention(now),
            Self::Postgres(_) => {
                Err("run_retention is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn purge_old_records(&self, before: i64) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.purge_old_records(before),
            Self::Postgres(_) => {
                Err("purge_old_records is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }
}
