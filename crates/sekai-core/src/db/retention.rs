//! Backend-neutral reusable retention policy persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::retention::{
    ArchiveRun, ArchiveStatus, ArchiveVerification, RetentionPolicy, SubjectErasureRequest,
    SubjectErasureResult,
};

pub trait RetentionPolicyBackend: Send + Sync {
    fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String>;
    fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String>;
    fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String>;
    /// One retention run into the in-database archive (ADR 0141).
    fn archive_retained_records(&self, now: i64, dry_run: bool) -> Result<ArchiveRun, String>;
    fn verify_retention_archive(&self) -> Result<ArchiveVerification, String>;
    fn retention_archive_status(&self) -> Result<ArchiveStatus, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
            <$target>::set_retention_policy(self, policy)
        }
        fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
            <$target>::list_retention_policies(self)
        }
        fn erase_subject(
            &self,
            request: &SubjectErasureRequest,
        ) -> Result<SubjectErasureResult, String> {
            <$target>::erase_subject(self, request)
        }
        fn archive_retained_records(&self, now: i64, dry_run: bool) -> Result<ArchiveRun, String> {
            <$target>::archive_retained_records(self, now, dry_run)
        }
        fn verify_retention_archive(&self) -> Result<ArchiveVerification, String> {
            <$target>::verify_retention_archive(self)
        }
        fn retention_archive_status(&self) -> Result<ArchiveStatus, String> {
            <$target>::retention_archive_status(self)
        }
    };
}

impl RetentionPolicyBackend for SekaiDb {
    forward!(SekaiDb);
}
impl RetentionPolicyBackend for PostgresDb {
    forward!(PostgresDb);
}
