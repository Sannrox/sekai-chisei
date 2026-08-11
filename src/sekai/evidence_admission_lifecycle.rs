//! Ordered admission of external evidence into durable graph state.
//!
//! Transport and producer adapters authenticate callers and translate their
//! protocols. This module owns admission, execution-evidence validation and
//! rejection, graph projection, execution recording, and final durable-state
//! resolution behind one domain-shaped interface.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::evidence::EvidenceEnvelope;
use crate::sekai::evidence_projection::EvidenceProjectionOutcome;
use crate::sekai::evidence_store::EvidenceSubmissionRecord;
use crate::sekai::execution_evidence::EXECUTION_EVIDENCE_TYPE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EvidenceAdmissionLifecycleError {
    Admission(String),
    Rejection(String),
    Projection(String),
    ExecutionRecording(String),
    ResultResolution(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EvidenceAdmissionOutcome {
    pub(crate) submission: EvidenceSubmissionRecord,
    pub(crate) admitted: bool,
    pub(crate) deduplicated: bool,
    pub(crate) projection: Option<EvidenceProjectionOutcome>,
    pub(crate) execution_recorded: bool,
}

pub(crate) struct EvidenceAdmissionLifecycle<'a> {
    db: &'a RuntimeDb,
}

impl<'a> EvidenceAdmissionLifecycle<'a> {
    pub(crate) fn new(db: &'a RuntimeDb) -> Self {
        Self { db }
    }

    pub(crate) fn admit(
        &self,
        envelope: &EvidenceEnvelope,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceAdmissionOutcome, EvidenceAdmissionLifecycleError> {
        let mut admission = self
            .db
            .submit_evidence(envelope, authenticated_producer, now_ms)
            .map_err(EvidenceAdmissionLifecycleError::Admission)?;
        let is_execution_evidence = admission.submission.evidence_type == EXECUTION_EVIDENCE_TYPE;

        if admission.accepted
            && is_execution_evidence
            && let Err(error) = self
                .db
                .validate_execution_evidence_envelope(envelope, authenticated_producer)
        {
            admission = self
                .db
                .reject_evidence_submission(
                    &admission.submission.id,
                    now_ms,
                    "invalid_execution_evidence",
                    &error,
                )
                .map_err(EvidenceAdmissionLifecycleError::Rejection)?;
        }

        let projection = admission
            .accepted
            .then(|| {
                self.db
                    .project_evidence_submission(&admission.submission.id, now_ms)
                    .map_err(EvidenceAdmissionLifecycleError::Projection)
            })
            .transpose()?;

        let execution_recorded = if admission.accepted && is_execution_evidence {
            self.db
                .record_execution_evidence(&admission.submission.id)
                .map_err(EvidenceAdmissionLifecycleError::ExecutionRecording)?
        } else {
            false
        };

        let submission = self
            .db
            .get_evidence_submission(&admission.submission.id)
            .map_err(EvidenceAdmissionLifecycleError::ResultResolution)?
            .ok_or_else(|| {
                EvidenceAdmissionLifecycleError::ResultResolution(
                    "evidence submission disappeared".into(),
                )
            })?;

        Ok(EvidenceAdmissionOutcome {
            submission,
            admitted: admission.accepted,
            deduplicated: admission.deduplicated,
            projection,
            execution_recorded,
        })
    }
}
