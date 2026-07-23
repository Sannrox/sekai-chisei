//! Backend-neutral reusable retention policy persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::retention::{RetentionPolicy, SubjectErasureRequest, SubjectErasureResult};

pub trait RetentionPolicyBackend: Send + Sync {
    fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String>;
    fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String>;
    fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String>;
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
    };
}

impl RetentionPolicyBackend for SekaiDb {
    forward!(SekaiDb);
}
impl RetentionPolicyBackend for PostgresDb {
    forward!(PostgresDb);
}
