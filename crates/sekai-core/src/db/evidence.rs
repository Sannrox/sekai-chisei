//! Backend-neutral reusable evidence admission persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::evidence::{EvidenceEnvelope, EvidenceLifecycleState};
use crate::sekai::evidence_projection::EvidenceProjectionOutcome;
use crate::sekai::evidence_store::{
    EvidenceAdmission, EvidenceProducerCapability, EvidenceSchemaDefinition,
    EvidenceSubmissionFilter, EvidenceSubmissionRecord,
};

pub trait EvidenceBackend: Send + Sync {
    fn upsert_evidence_producer(
        &self,
        capability: &EvidenceProducerCapability,
        now_ms: i64,
    ) -> Result<(), String>;
    fn register_evidence_schema(
        &self,
        definition: &EvidenceSchemaDefinition,
        now_ms: i64,
    ) -> Result<(), String>;
    fn submit_evidence(
        &self,
        envelope: &EvidenceEnvelope,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceAdmission, String>;
    fn get_evidence_submission(
        &self,
        submission_id: &str,
    ) -> Result<Option<EvidenceSubmissionRecord>, String>;
    fn evidence_lifecycle_history(
        &self,
        submission_id: &str,
    ) -> Result<Vec<EvidenceLifecycleState>, String>;
    fn list_evidence_submissions(
        &self,
        filter: &EvidenceSubmissionFilter,
    ) -> Result<Vec<EvidenceSubmissionRecord>, String>;
    fn project_evidence_submission(
        &self,
        submission_id: &str,
        now_ms: i64,
    ) -> Result<EvidenceProjectionOutcome, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn upsert_evidence_producer(
            &self,
            value: &EvidenceProducerCapability,
            now: i64,
        ) -> Result<(), String> {
            <$target>::upsert_evidence_producer(self, value, now)
        }
        fn register_evidence_schema(
            &self,
            value: &EvidenceSchemaDefinition,
            now: i64,
        ) -> Result<(), String> {
            <$target>::register_evidence_schema(self, value, now)
        }
        fn submit_evidence(
            &self,
            value: &EvidenceEnvelope,
            producer: &str,
            now: i64,
        ) -> Result<EvidenceAdmission, String> {
            <$target>::submit_evidence(self, value, producer, now)
        }
        fn get_evidence_submission(
            &self,
            id: &str,
        ) -> Result<Option<EvidenceSubmissionRecord>, String> {
            <$target>::get_evidence_submission(self, id)
        }
        fn evidence_lifecycle_history(
            &self,
            id: &str,
        ) -> Result<Vec<EvidenceLifecycleState>, String> {
            <$target>::evidence_lifecycle_history(self, id)
        }
        fn list_evidence_submissions(
            &self,
            filter: &EvidenceSubmissionFilter,
        ) -> Result<Vec<EvidenceSubmissionRecord>, String> {
            <$target>::list_evidence_submissions(self, filter)
        }
        fn project_evidence_submission(
            &self,
            id: &str,
            now: i64,
        ) -> Result<EvidenceProjectionOutcome, String> {
            <$target>::project_evidence_submission(self, id, now)
        }
    };
}

impl EvidenceBackend for SekaiDb {
    forward!(SekaiDb);
}
impl EvidenceBackend for PostgresDb {
    forward!(PostgresDb);
}
