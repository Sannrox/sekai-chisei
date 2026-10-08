//! Sekai-side adapters into Chisei projections (ADR 0092 rule 5).
//!
//! Chisei owns the System One fill and the epistemic descriptor; it reads only
//! Chisei types. This module maps Sekai governed Action types, evidence
//! submissions, and retrieval explanations into them.

use sekai_provider::system_one::SystemOneBind;

use crate::chisei::epistemic_descriptor::{EpistemicDescriptor, ExternalEvidenceFacts};
use crate::chisei::system_one_action::SystemOneActionType;
use crate::sekai::evidence_store::EvidenceSubmissionRecord;
use crate::sekai::governed_action_type::GovernedActionType;
use crate::sekai::retrieval::Explanation;

impl SystemOneActionType for GovernedActionType {
    fn type_id(&self) -> &str {
        &self.type_id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn parameter_schema_json(&self) -> &str {
        &self.parameter_schema_json
    }

    fn system_one(&self) -> Option<&SystemOneBind> {
        self.system_one.as_ref()
    }
}

impl EvidenceSubmissionRecord {
    /// Epistemic descriptor for this admitted evidence row. The payload is
    /// never copied; only identity, digest, lifecycle, observation time, and
    /// producer confidence are projected.
    pub fn epistemic_descriptor(&self) -> EpistemicDescriptor {
        EpistemicDescriptor::from_external_evidence(&ExternalEvidenceFacts {
            id: &self.id,
            content_digest: &self.content_digest,
            lifecycle_state: self.lifecycle_state,
            observed_at_ms: self.observed_at_ms,
            envelope_confidence_bps: self
                .envelope
                .as_ref()
                .map(|envelope| envelope.confidence_bps),
        })
    }
}

/// Project an authorization-filtered graph retrieval explanation. The
/// explanation is already the source of truth for whether a result was
/// asserted or entailed; evidence polarity is not inferred from graph shape.
pub fn graph_explanation_descriptor(
    explanation: &Explanation,
    source_rows_truncated: bool,
) -> EpistemicDescriptor {
    EpistemicDescriptor::from_graph_projection(
        explanation.derived,
        &explanation.source_fact_ids,
        &explanation.ontology_revision,
        source_rows_truncated,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::epistemic_descriptor::{EvidenceStatus, OriginClass};
    use crate::sekai::evidence_vocabulary::{
        EvidenceClassification, EvidenceIntent, EvidenceLifecycleState,
    };

    #[test]
    fn external_projection_does_not_copy_payload() {
        let submission = EvidenceSubmissionRecord {
            id: "submission-1".into(),
            producer_identity: "producer".into(),
            source_type: "ci".into(),
            source_instance: "runner".into(),
            source_record_id: "record".into(),
            source_version: "1".into(),
            source_sequence: 1,
            namespace: "demo".into(),
            target_external_id: "service:api".into(),
            target_kind: "component".into(),
            evidence_type: "verification".into(),
            schema_id: "schema".into(),
            schema_version: "1".into(),
            idempotency_key: "key".into(),
            content_digest: "digest".into(),
            classification: EvidenceClassification::Public,
            intent: EvidenceIntent::Upsert,
            lifecycle_state: EvidenceLifecycleState::Available,
            rejection_code: None,
            rejection_summary: None,
            observed_at_ms: 42,
            collected_at_ms: 42,
            expires_at_ms: None,
            received_at_ms: 42,
            updated_at_ms: 42,
            envelope: None,
        };
        let descriptor = submission.epistemic_descriptor();
        assert_eq!(descriptor.origin_class, OriginClass::Asserted);
        assert_eq!(descriptor.evidence_status, EvidenceStatus::Unknown);
        assert_eq!(descriptor.source_refs, vec!["submission-1"]);
        assert!(descriptor.validate().is_ok());
    }
}
