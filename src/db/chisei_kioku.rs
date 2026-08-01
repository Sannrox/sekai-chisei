//! Backend-neutral Kioku memory persistence.

use crate::chisei::kioku::{
    HumanMemoryReview, KiokuCandidateCursor, KiokuEvidenceAuthorizationRequest, KiokuEvidenceLink,
    KiokuEvidenceReassessmentRequest, KiokuEvidenceReassessmentResult, KiokuMemory,
    MemoryLifecycleEvent, MemoryValidation, derive_evidence_reassessment_candidate,
    kioku_reassessment_candidate_id, merge_evidence_basis,
};
use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::evidence::EvidenceClassification;

pub trait ChiseiKiokuBackend: Send + Sync {
    fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String>;
    fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String>;
    fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String>;
    fn list_kioku_candidate_page(
        &self,
        namespace: &str,
        limit: usize,
        cursor: Option<&KiokuCandidateCursor>,
    ) -> Result<Vec<KiokuMemory>, String>;
    fn list_kioku_evidence(&self, id: &str, version: u32)
    -> Result<Vec<KiokuEvidenceLink>, String>;
    fn validate_kioku_candidate(&self, id: &str, version: u32) -> Result<MemoryValidation, String>;
    fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String>;
    fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String>;
    fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String>;
    fn disable_kioku_memory(
        &self,
        id: &str,
        version: u32,
        actor: &str,
        rationale: &str,
        recorded_at_ms: i64,
    ) -> Result<KiokuMemory, String>;
    fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String>;
    fn authorize_kioku_evidence(
        &self,
        request: &KiokuEvidenceAuthorizationRequest,
    ) -> Result<(), String>;
    fn reassess_kioku_memory(
        &self,
        request: KiokuEvidenceReassessmentRequest,
    ) -> Result<KiokuEvidenceReassessmentResult, String> {
        if request.memory_id.trim().is_empty() || request.memory_version == 0 {
            return Err("reassessment memory reference is required".into());
        }
        if request.actor.trim().is_empty() {
            return Err("reassessment actor is required".into());
        }
        if request.reassessment_key.trim().is_empty()
            || request.reassessment_key.chars().count() > 128
            || request.reassessment_key.chars().any(char::is_control)
        {
            return Err("reassessment_key is required and must be bounded".into());
        }
        if request.evidence_basis.is_empty() {
            return Err("reassessment requires at least one evidence basis entry".into());
        }
        for basis in &request.evidence_basis {
            basis.validate()?;
            if basis.observed_at_ms > request.now_ms {
                return Err("evidence observed_at_ms cannot be in the future".into());
            }
        }
        let prior = self
            .get_kioku_memory(&request.memory_id, request.memory_version)?
            .ok_or_else(|| "active memory version not found".to_string())?;
        let prior_evidence = self.list_kioku_evidence(&prior.id, prior.version)?;
        let baseline_basis = if prior.evidence_basis.is_empty() {
            prior_evidence
                .iter()
                .map(|link| crate::chisei::kioku::KiokuEvidenceBasis {
                    evidence_reference: link.evidence_reference.clone(),
                    evidence_digest: link.evidence_digest.clone(),
                    source_submission_id: String::new(),
                    stance: link.stance,
                    lifecycle_state: crate::sekai::evidence::EvidenceLifecycleState::Available,
                    observed_at_ms: link.observed_at_ms,
                })
                .collect::<Vec<_>>()
        } else {
            prior.evidence_basis.clone()
        };
        for basis in &request.evidence_basis {
            if basis.source_submission_id.trim().is_empty() {
                let prior_basis = baseline_basis
                    .iter()
                    .find(|prior_basis| {
                        prior_basis.source_submission_id.is_empty()
                            && prior_basis.evidence_reference == basis.evidence_reference
                            && prior_basis.evidence_digest == basis.evidence_digest
                    })
                    .or_else(|| {
                        baseline_basis.iter().find(|prior_basis| {
                            prior_basis.source_submission_id.is_empty()
                                && prior_basis.evidence_reference == basis.evidence_reference
                        })
                    })
                    .ok_or_else(|| {
                        "new evidence basis entries must bind an evidence submission".to_string()
                    })?;
                if prior_basis.evidence_digest != basis.evidence_digest {
                    return Err(
                        "unbound evidence basis must preserve the exact prior digest".into(),
                    );
                }
                if prior_basis.observed_at_ms != basis.observed_at_ms {
                    return Err(
                        "unbound evidence basis must preserve the authoritative observation time"
                            .into(),
                    );
                }
                if !prior_basis.source_submission_id.is_empty() {
                    return Err(
                        "evidence basis cannot drop its governed submission identity".into(),
                    );
                }
            }
        }
        let merged_basis =
            merge_evidence_basis(&baseline_basis, &request.evidence_basis, request.now_ms)?;
        let merged_basis_digest =
            crate::chisei::kioku::canonical_evidence_basis_digest(&merged_basis);
        let candidate_id = kioku_reassessment_candidate_id(
            &request.memory_id,
            request.memory_version,
            &request.reassessment_key,
        );
        if let Some(existing) = self.get_kioku_memory(&candidate_id, 1)? {
            if existing.reassessment_key == request.reassessment_key
                && existing.supersedes.as_ref().is_some_and(|supersedes| {
                    supersedes.memory_id == request.memory_id
                        && supersedes.version == request.memory_version
                })
                && existing.evidence_basis_digest == merged_basis_digest
            {
                let existing_evidence = self.list_kioku_evidence(&existing.id, existing.version)?;
                return Ok(KiokuEvidenceReassessmentResult {
                    candidate: existing,
                    evidence: existing_evidence,
                    idempotent: true,
                });
            }
            return Err("reassessment key conflicts with a different evidence basis".into());
        }
        let ceiling =
            self.kioku_authorized_classification_ceiling(&prior.namespace, &request.actor)?;
        if prior.classification > ceiling {
            return Err("memory classification exceeds actor grant".into());
        }
        // Reauthorize every entry in the merged basis, including entries that
        // were carried forward unchanged. Governed evidence may have changed
        // lifecycle, retention, classification, or projection grants since
        // the prior memory version was admitted.
        for basis in &merged_basis {
            if basis.source_submission_id.is_empty() {
                let prior_basis = baseline_basis
                    .iter()
                    .find(|prior_basis| {
                        prior_basis.source_submission_id.is_empty()
                            && prior_basis.evidence_reference == basis.evidence_reference
                            && prior_basis.evidence_digest == basis.evidence_digest
                    })
                    .ok_or_else(|| {
                        "unbound evidence basis must preserve an existing evidence identity"
                            .to_string()
                    })?;
                if prior_basis.observed_at_ms != basis.observed_at_ms {
                    return Err(
                        "unbound evidence basis must preserve the authoritative observation time"
                            .into(),
                    );
                }
            } else {
                self.authorize_kioku_evidence(&KiokuEvidenceAuthorizationRequest {
                    source_submission_id: basis.source_submission_id.clone(),
                    namespace: prior.namespace.clone(),
                    memory_classification: prior.classification,
                    evidence_digest: basis.evidence_digest.clone(),
                    lifecycle_state: basis.lifecycle_state,
                    observed_at_ms: basis.observed_at_ms,
                    actor: request.actor.clone(),
                    now_ms: request.now_ms,
                })?;
            }
        }
        if prior.state != crate::chisei::kioku::MemoryLifecycleState::Active {
            return Err("only active memories can be reassessed".into());
        }
        let (candidate, evidence) =
            derive_evidence_reassessment_candidate(&prior, &prior_evidence, &request)?;
        match self.insert_kioku_memory(&candidate, &evidence) {
            Ok(()) => Ok(KiokuEvidenceReassessmentResult {
                candidate,
                evidence,
                idempotent: false,
            }),
            Err(error) => {
                if let Some(existing) = self.get_kioku_memory(&candidate.id, candidate.version)? {
                    if existing.reassessment_key == candidate.reassessment_key
                        && existing.supersedes == candidate.supersedes
                        && existing.evidence_basis_digest == candidate.evidence_basis_digest
                    {
                        let existing_evidence =
                            self.list_kioku_evidence(&existing.id, existing.version)?;
                        return Ok(KiokuEvidenceReassessmentResult {
                            candidate: existing,
                            evidence: existing_evidence,
                            idempotent: true,
                        });
                    }
                    return Err("reassessment key conflicts with a different evidence basis".into());
                }
                Err(error)
            }
        }
    }
}

macro_rules! forward {
    ($target:ty) => {
        fn insert_kioku_memory(
            &self,
            memory: &KiokuMemory,
            evidence: &[KiokuEvidenceLink],
        ) -> Result<(), String> {
            <$target>::insert_kioku_memory(self, memory, evidence)
        }
        fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
            <$target>::get_kioku_memory(self, id, version)
        }
        fn list_kioku_candidates(
            &self,
            namespace: &str,
            operation_class: Option<&str>,
            limit: usize,
        ) -> Result<Vec<KiokuMemory>, String> {
            <$target>::list_kioku_candidates(self, namespace, operation_class, limit)
        }
        fn list_kioku_candidate_page(
            &self,
            namespace: &str,
            limit: usize,
            cursor: Option<&KiokuCandidateCursor>,
        ) -> Result<Vec<KiokuMemory>, String> {
            <$target>::list_kioku_candidate_page(self, namespace, limit, cursor)
        }
        fn list_kioku_evidence(
            &self,
            id: &str,
            version: u32,
        ) -> Result<Vec<KiokuEvidenceLink>, String> {
            <$target>::list_kioku_evidence(self, id, version)
        }
        fn validate_kioku_candidate(
            &self,
            id: &str,
            version: u32,
        ) -> Result<MemoryValidation, String> {
            <$target>::validate_kioku_candidate(self, id, version)
        }
        fn review_kioku_candidate(
            &self,
            id: &str,
            version: u32,
            review: HumanMemoryReview,
        ) -> Result<KiokuMemory, String> {
            <$target>::review_kioku_candidate(self, id, version, review)
        }
        fn list_kioku_lifecycle_events(
            &self,
            id: &str,
            version: u32,
        ) -> Result<Vec<MemoryLifecycleEvent>, String> {
            <$target>::list_kioku_lifecycle_events(self, id, version)
        }
        fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
            <$target>::record_kioku_lifecycle_event(self, event)
        }
        fn disable_kioku_memory(
            &self,
            id: &str,
            version: u32,
            actor: &str,
            rationale: &str,
            recorded_at_ms: i64,
        ) -> Result<KiokuMemory, String> {
            <$target>::disable_kioku_memory(self, id, version, actor, rationale, recorded_at_ms)
        }
        fn kioku_authorized_classification_ceiling(
            &self,
            namespace: &str,
            actor: &str,
        ) -> Result<EvidenceClassification, String> {
            <$target>::kioku_authorized_classification_ceiling(self, namespace, actor)
        }
        fn authorize_kioku_evidence(
            &self,
            request: &KiokuEvidenceAuthorizationRequest,
        ) -> Result<(), String> {
            <$target>::authorize_kioku_evidence(self, request)
        }
    };
}

impl ChiseiKiokuBackend for SekaiDb {
    forward!(SekaiDb);
}
impl ChiseiKiokuBackend for PostgresDb {
    forward!(PostgresDb);
}
