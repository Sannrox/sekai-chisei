//! Bounded, source-neutral epistemic metadata for existing Chisei references.
//!
//! The descriptor is a projection, not a new authority.  Its three dimensions
//! deliberately remain independent: an item can be asserted, have unknown
//! evidence status, and be current without those values being collapsed into a
//! single trust enum.  Constructors in this module only use fields that are
//! already authoritative for the source being projected.

use crate::chisei::kioku::{KiokuEvidenceLink, KiokuMemory, MemoryEvidenceStance};
use crate::sekai::evidence::EvidenceLifecycleState;
use crate::sekai::evidence_store::EvidenceSubmissionRecord;
use serde::{Deserialize, Serialize};

pub const EPISTEMIC_DESCRIPTOR_VERSION: &str = "chisei.epistemic-descriptor/v1";
pub const MAX_SOURCE_REFS: usize = 8;
pub const MAX_SOURCE_DIGESTS: usize = 8;
pub const MAX_SOURCE_ROWS: usize = 128;
pub const MAX_SOURCE_ITEM_BYTES: usize = 256;
pub const MAX_DERIVATION_REF_BYTES: usize = 128;
pub const MAX_DESCRIPTOR_BYTES: usize = 4 * 1024;
pub const MAX_OBSERVED_AT_MS: i64 = 4_102_444_800_000; // 2100-01-01T00:00:00Z

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginClass {
    Asserted,
    Derived,
    Hypothesis,
    Unknown,
}

impl OriginClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asserted => "asserted",
            Self::Derived => "derived",
            Self::Hypothesis => "hypothesis",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Supported,
    Contested,
    Insufficient,
    Unknown,
}

impl EvidenceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Contested => "contested",
            Self::Insufficient => "insufficient",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    Current,
    Stale,
    Retracted,
    Superseded,
    Unknown,
}

impl LifecycleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Retracted => "retracted",
            Self::Superseded => "superseded",
            Self::Unknown => "unknown",
        }
    }
}

/// Additive metadata projected onto an existing context reference.
///
/// Source references, digests, derivation identifiers, counts, and observation
/// timing are populated only by an already-authorized source projection.  The
/// descriptor never contains source payload or a system-computed trust score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicDescriptor {
    pub contract_version: String,
    pub origin_class: OriginClass,
    pub evidence_status: EvidenceStatus,
    pub lifecycle_status: LifecycleStatus,
    pub producer_confidence_bps: Option<u16>,
    pub confidence_basis: Option<String>,
    pub observed_at_ms: Option<i64>,
    pub derivation_ref: Option<String>,
    pub source_refs: Vec<String>,
    pub source_digests: Vec<String>,
    pub source_row_count: Option<u32>,
    pub source_rows_truncated: bool,
    pub supporting_evidence_count: Option<u32>,
    pub contradicting_evidence_count: Option<u32>,
}

impl EpistemicDescriptor {
    pub fn unknown() -> Self {
        Self {
            contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
            origin_class: OriginClass::Unknown,
            evidence_status: EvidenceStatus::Unknown,
            lifecycle_status: LifecycleStatus::Unknown,
            producer_confidence_bps: None,
            confidence_basis: None,
            observed_at_ms: None,
            derivation_ref: None,
            source_refs: Vec::new(),
            source_digests: Vec::new(),
            source_row_count: None,
            source_rows_truncated: false,
            supporting_evidence_count: None,
            contradicting_evidence_count: None,
        }
    }

    /// Project an authorization-filtered graph retrieval explanation.  The
    /// explanation is already the source of truth for whether a result was
    /// asserted or entailed; this constructor does not infer evidence
    /// polarity from graph shape or object properties.
    pub fn from_graph_explanation(
        explanation: &crate::sekai::retrieval::Explanation,
        source_rows_truncated: bool,
    ) -> Self {
        Self::from_graph_projection(
            explanation.derived,
            &explanation.source_fact_ids,
            &explanation.ontology_revision,
            source_rows_truncated,
        )
    }

    /// Projection form used by transport adapters that already serialized the
    /// authorization-filtered explanation.
    pub fn from_graph_projection(
        derived: bool,
        source_fact_ids: &[String],
        ontology_revision: &str,
        source_rows_truncated: bool,
    ) -> Self {
        let source_row_count = source_fact_ids.len().min(MAX_SOURCE_ROWS) as u32;
        let derivation_ref = if derived {
            bounded_optional_string(&format!("ontology_revision:{}", ontology_revision))
        } else {
            None
        };
        Self {
            contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
            origin_class: if derived {
                OriginClass::Derived
            } else {
                OriginClass::Asserted
            },
            evidence_status: EvidenceStatus::Unknown,
            lifecycle_status: LifecycleStatus::Current,
            producer_confidence_bps: None,
            confidence_basis: None,
            observed_at_ms: None,
            derivation_ref,
            source_refs: source_fact_ids
                .iter()
                .filter_map(|value| bounded_source_string(value))
                .take(MAX_SOURCE_REFS)
                .collect(),
            source_digests: Vec::new(),
            source_row_count: Some(source_row_count),
            source_rows_truncated: source_rows_truncated || source_fact_ids.len() > MAX_SOURCE_ROWS,
            supporting_evidence_count: None,
            contradicting_evidence_count: None,
        }
        .fit_byte_bound()
    }

    /// Project a request-scoped scenario impact row.  Scenario evaluation is
    /// not evidence evaluation: the hypothesis origin is explicit while the
    /// evidence and lifecycle dimensions remain unknown.
    pub fn from_hypothesis(
        scenario_id: &str,
        source_refs: &[String],
        source_row_count: usize,
        source_rows_truncated: bool,
    ) -> Self {
        Self {
            contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
            origin_class: OriginClass::Hypothesis,
            evidence_status: EvidenceStatus::Unknown,
            lifecycle_status: LifecycleStatus::Unknown,
            producer_confidence_bps: None,
            confidence_basis: None,
            observed_at_ms: None,
            derivation_ref: bounded_optional_string(&format!("scenario:{scenario_id}")),
            source_refs: source_refs
                .iter()
                .filter_map(|value| bounded_source_string(value))
                .take(MAX_SOURCE_REFS)
                .collect(),
            source_digests: Vec::new(),
            source_row_count: Some(source_row_count.min(MAX_SOURCE_ROWS) as u32),
            source_rows_truncated: source_rows_truncated || source_row_count > MAX_SOURCE_ROWS,
            supporting_evidence_count: None,
            contradicting_evidence_count: None,
        }
        .fit_byte_bound()
    }

    /// Project a retrieved Kioku memory after the normal Kioku authorization
    /// and classification checks have succeeded.
    pub fn from_kioku(memory: &KiokuMemory, evidence: &[KiokuEvidenceLink]) -> Self {
        let supporting = evidence
            .iter()
            .filter(|link| link.stance == MemoryEvidenceStance::Supporting)
            .count();
        let contradicting = evidence
            .iter()
            .filter(|link| link.stance == MemoryEvidenceStance::Contradicting)
            .count();
        let evidence_status = if supporting == 0 {
            if contradicting == 0 {
                EvidenceStatus::Insufficient
            } else {
                EvidenceStatus::Contested
            }
        } else if contradicting > 0 {
            EvidenceStatus::Contested
        } else {
            EvidenceStatus::Supported
        };
        let lifecycle_status = match memory.state.as_str() {
            "active" => LifecycleStatus::Current,
            "superseded" => LifecycleStatus::Superseded,
            "rejected" => LifecycleStatus::Retracted,
            // Candidate is not an admitted planning reference.  Keep this
            // branch conservative if a future caller projects one anyway.
            _ => LifecycleStatus::Unknown,
        };
        let origin_class = match memory.derivation_method.as_str() {
            // This is the only derivation contract currently authoritative in
            // Kioku.  Other producer labels must remain unknown, not guessed.
            "verified_binary_outcomes/v1" => OriginClass::Derived,
            _ => OriginClass::Unknown,
        };
        let observed_at_ms = evidence
            .iter()
            .map(|link| link.observed_at_ms)
            .filter(|value| (0..=MAX_OBSERVED_AT_MS).contains(value))
            .max()
            .or_else(|| memory.last_confirmed_at_ms.and_then(bounded_observed_at))
            .or_else(|| bounded_observed_at(memory.created_at_ms));
        let source_refs = evidence
            .iter()
            .filter_map(|link| bounded_source_string(&link.operation_id))
            .take(MAX_SOURCE_REFS)
            .collect();
        // A Kioku memory's classification authorizes the memory projection,
        // not each linked receipt/evidence source.  Do not introduce a new
        // digest disclosure path without a source-level authorization check.
        let source_digests = Vec::new();
        let producer_confidence_bps =
            (memory.confidence_bps <= 10_000).then_some(memory.confidence_bps);
        Self {
            contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
            origin_class,
            evidence_status,
            lifecycle_status,
            producer_confidence_bps,
            confidence_basis: producer_confidence_bps.map(|_| "producer_input".into()),
            observed_at_ms,
            derivation_ref: bounded_optional_string(&memory.derivation_method),
            source_refs,
            source_digests,
            source_row_count: Some(evidence.len().min(MAX_SOURCE_ROWS) as u32),
            source_rows_truncated: evidence.len() > MAX_SOURCE_ROWS,
            supporting_evidence_count: Some(supporting.min(u32::MAX as usize) as u32),
            contradicting_evidence_count: Some(contradicting.min(u32::MAX as usize) as u32),
        }
        .fit_byte_bound()
    }

    /// Project an admitted external evidence row.  The row's source envelope
    /// is an assertion and its lifecycle is authoritative; polarity is not
    /// inferred from the evidence signal, so evidence status remains unknown.
    pub fn from_external_evidence(submission: &EvidenceSubmissionRecord) -> Self {
        let lifecycle_status = match submission.lifecycle_state {
            EvidenceLifecycleState::Available => LifecycleStatus::Current,
            EvidenceLifecycleState::Stale => LifecycleStatus::Stale,
            EvidenceLifecycleState::Retracted => LifecycleStatus::Retracted,
            EvidenceLifecycleState::Superseded => LifecycleStatus::Superseded,
            _ => LifecycleStatus::Unknown,
        };
        let producer_confidence_bps = submission
            .envelope
            .as_ref()
            .map(|envelope| envelope.confidence_bps)
            .filter(|value| *value <= 10_000);
        Self {
            contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
            origin_class: OriginClass::Asserted,
            evidence_status: EvidenceStatus::Unknown,
            lifecycle_status,
            producer_confidence_bps,
            confidence_basis: producer_confidence_bps.map(|_| "producer_input".into()),
            observed_at_ms: bounded_observed_at(submission.observed_at_ms),
            derivation_ref: None,
            source_refs: bounded_source_string(&submission.id).into_iter().collect(),
            source_digests: bounded_source_string(&submission.content_digest)
                .into_iter()
                .collect(),
            source_row_count: Some(1),
            source_rows_truncated: false,
            supporting_evidence_count: None,
            contradicting_evidence_count: None,
        }
        .fit_byte_bound()
    }

    /// Keep construction within the aggregate wire/documentation bound even
    /// when every independent source-item cap is reached.  Source lists are
    /// ordered by the admitted source and are trimmed from the tail only;
    /// scalar dimensions remain authoritative and are never guessed.
    fn fit_byte_bound(mut self) -> Self {
        while serialized_len(&self) > MAX_DESCRIPTOR_BYTES
            && (!self.source_refs.is_empty() || !self.source_digests.is_empty())
        {
            let refs_bytes: usize = self.source_refs.iter().map(String::len).sum();
            let digests_bytes: usize = self.source_digests.iter().map(String::len).sum();
            if digests_bytes >= refs_bytes && !self.source_digests.is_empty() {
                self.source_digests.pop();
            } else if !self.source_refs.is_empty() {
                self.source_refs.pop();
            } else {
                self.source_digests.pop();
            }
        }
        if serialized_len(&self) <= MAX_DESCRIPTOR_BYTES {
            self
        } else {
            // The current fixed fields are well below the bound.  Keep this
            // fail-closed fallback for future contract additions.
            Self::unknown()
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != EPISTEMIC_DESCRIPTOR_VERSION {
            return Err(format!(
                "unsupported epistemic descriptor version {}",
                self.contract_version
            ));
        }
        if self.source_refs.len() > MAX_SOURCE_REFS {
            return Err("epistemic descriptor source reference bound exceeded".into());
        }
        if self.source_digests.len() > MAX_SOURCE_DIGESTS {
            return Err("epistemic descriptor source digest bound exceeded".into());
        }
        if self
            .source_row_count
            .is_some_and(|count| count as usize > MAX_SOURCE_ROWS)
        {
            return Err("epistemic descriptor source row bound exceeded".into());
        }
        if self.source_rows_truncated && self.source_row_count.is_none() {
            return Err("truncated epistemic descriptor rows require a row count".into());
        }
        if self
            .derivation_ref
            .as_ref()
            .is_some_and(|value| value.len() > MAX_DERIVATION_REF_BYTES)
        {
            return Err("epistemic descriptor derivation reference bound exceeded".into());
        }
        if self
            .producer_confidence_bps
            .is_some_and(|value| value > 10_000)
        {
            return Err("epistemic descriptor confidence bound exceeded".into());
        }
        match (
            self.producer_confidence_bps,
            self.confidence_basis.as_deref(),
        ) {
            (Some(_), Some("producer_input")) | (None, None) => {}
            (Some(_), _) => {
                return Err("producer confidence requires producer_input basis".into());
            }
            (None, Some(_)) => {
                return Err("confidence basis requires producer confidence".into());
            }
        }
        if self
            .source_refs
            .iter()
            .chain(self.source_digests.iter())
            .any(|value| value.len() > MAX_SOURCE_ITEM_BYTES)
        {
            return Err("epistemic descriptor source item bound exceeded".into());
        }
        for value in self
            .source_refs
            .iter()
            .chain(self.source_digests.iter())
            .chain(self.confidence_basis.iter())
            .chain(self.derivation_ref.iter())
        {
            if value.bytes().any(|byte| byte.is_ascii_control()) {
                return Err("epistemic descriptor contains a control character".into());
            }
        }
        if self
            .observed_at_ms
            .is_some_and(|value| !(0..=MAX_OBSERVED_AT_MS).contains(&value))
        {
            return Err("epistemic descriptor observed_at_ms is outside the v1 bound".into());
        }
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_DESCRIPTOR_BYTES {
            return Err("epistemic descriptor byte bound exceeded".into());
        }
        Ok(())
    }
}

fn bounded_optional_string(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_DERIVATION_REF_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control()))
    .then(|| value.to_string())
}

fn bounded_source_string(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_SOURCE_ITEM_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control()))
    .then(|| value.to_string())
}

fn bounded_observed_at(value: i64) -> Option<i64> {
    (0..=MAX_OBSERVED_AT_MS).contains(&value).then_some(value)
}

fn serialized_len(descriptor: &EpistemicDescriptor) -> usize {
    serde_json::to_vec(descriptor)
        .map(|encoded| encoded.len())
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::kioku::{KiokuEvidenceLink, KiokuMemory, MemoryKind, MemoryLifecycleState};
    use crate::sekai::evidence::{EvidenceClassification, EvidenceIntent};

    fn memory(state: MemoryLifecycleState) -> KiokuMemory {
        KiokuMemory {
            contract_version: "kioku.memory/v1".into(),
            id: "memory-1".into(),
            version: 1,
            kind: MemoryKind::Claim,
            claim: "bounded claim".into(),
            namespace: "demo".into(),
            operation_classes: vec!["verification".into()],
            affinity_object_ids: vec![],
            outcome_definition: "passed".into(),
            confidence_bps: 8_500,
            sample_size: 2,
            uncertainty: "bounded".into(),
            producer_identity: "test".into(),
            derivation_method: "verified_binary_outcomes/v1".into(),
            classification: EvidenceClassification::Public,
            retention_until_ms: None,
            state,
            created_at_ms: 10,
            reviewed_at_ms: None,
            expires_at_ms: None,
            last_confirmed_at_ms: Some(20),
            supersedes: None,
            evidence_basis: vec![],
            evidence_basis_digest: String::new(),
            reassessment_key: String::new(),
            reassessment_actor: String::new(),
        }
    }

    fn link(stance: MemoryEvidenceStance, observed_at_ms: i64) -> KiokuEvidenceLink {
        KiokuEvidenceLink {
            memory_id: "memory-1".into(),
            memory_version: 1,
            operation_id: format!("operation-{observed_at_ms}"),
            verification_event_id: format!("event-{observed_at_ms}"),
            evidence_reference: "receipt".into(),
            evidence_digest: format!("digest-{observed_at_ms}"),
            stance,
            outcome_metric: "passed".into(),
            outcome_value: 1.0,
            observed_at_ms,
        }
    }

    #[test]
    fn unknown_descriptor_is_explicit_and_valid() {
        let descriptor = EpistemicDescriptor::unknown();
        assert_eq!(descriptor.origin_class, OriginClass::Unknown);
        assert_eq!(descriptor.evidence_status, EvidenceStatus::Unknown);
        assert_eq!(descriptor.lifecycle_status, LifecycleStatus::Unknown);
        descriptor.validate().unwrap();
    }

    #[test]
    fn graph_projection_distinguishes_asserted_and_entailed_results() {
        let asserted = EpistemicDescriptor::from_graph_projection(
            false,
            &["object-1".into(), "link-1".into()],
            "",
            false,
        );
        assert_eq!(asserted.origin_class, OriginClass::Asserted);
        assert_eq!(asserted.evidence_status, EvidenceStatus::Unknown);
        assert_eq!(asserted.lifecycle_status, LifecycleStatus::Current);
        assert!(asserted.derivation_ref.is_none());
        asserted.validate().unwrap();

        let derived = EpistemicDescriptor::from_graph_projection(
            true,
            &["link-1".into(), "ontology:class:Widget".into()],
            "rev-1",
            false,
        );
        assert_eq!(derived.origin_class, OriginClass::Derived);
        assert_eq!(derived.evidence_status, EvidenceStatus::Unknown);
        assert_eq!(
            derived.derivation_ref.as_deref(),
            Some("ontology_revision:rev-1")
        );
        assert_eq!(derived.source_refs.len(), 2);
        derived.validate().unwrap();
    }

    #[test]
    fn hypothesis_projection_never_mints_support_or_assertion() {
        let refs = vec!["delta-1".into(), "object-1".into()];
        let descriptor = EpistemicDescriptor::from_hypothesis("scenario-1", &refs, 2, false);
        assert_eq!(descriptor.origin_class, OriginClass::Hypothesis);
        assert_eq!(descriptor.evidence_status, EvidenceStatus::Unknown);
        assert_eq!(descriptor.lifecycle_status, LifecycleStatus::Unknown);
        assert_eq!(
            descriptor.derivation_ref.as_deref(),
            Some("scenario:scenario-1")
        );
        assert!(descriptor.producer_confidence_bps.is_none());
        descriptor.validate().unwrap();
    }

    #[test]
    fn kioku_projection_keeps_mixed_evidence_contested_and_bounded() {
        let evidence = vec![
            link(MemoryEvidenceStance::Supporting, 40),
            link(MemoryEvidenceStance::Contradicting, 50),
        ];
        let descriptor =
            EpistemicDescriptor::from_kioku(&memory(MemoryLifecycleState::Active), &evidence);
        assert_eq!(descriptor.origin_class, OriginClass::Derived);
        assert_eq!(descriptor.evidence_status, EvidenceStatus::Contested);
        assert_eq!(descriptor.lifecycle_status, LifecycleStatus::Current);
        assert_eq!(descriptor.observed_at_ms, Some(50));
        assert_eq!(descriptor.supporting_evidence_count, Some(1));
        assert_eq!(descriptor.contradicting_evidence_count, Some(1));
        assert!(descriptor.source_digests.is_empty());
        descriptor.validate().unwrap();
    }

    #[test]
    fn kioku_projection_does_not_disclose_linked_source_digests() {
        let descriptor = EpistemicDescriptor::from_kioku(
            &memory(MemoryLifecycleState::Active),
            &[link(MemoryEvidenceStance::Supporting, 40)],
        );
        assert!(descriptor.source_digests.is_empty());
    }

    #[test]
    fn validation_rejects_raw_control_data_and_oversized_rows() {
        let mut descriptor = EpistemicDescriptor::unknown();
        descriptor.source_row_count = Some((MAX_SOURCE_ROWS + 1) as u32);
        assert!(descriptor.validate().is_err());
        descriptor.source_row_count = None;
        descriptor.source_refs.push("bad\nvalue".into());
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn kioku_projection_enforces_aggregate_byte_bound() {
        let mut evidence = (0..MAX_SOURCE_REFS.max(MAX_SOURCE_DIGESTS))
            .map(|index| link(MemoryEvidenceStance::Supporting, index as i64 + 1))
            .collect::<Vec<_>>();
        for link in &mut evidence {
            link.operation_id = "r".repeat(MAX_SOURCE_ITEM_BYTES);
            link.evidence_digest = "d".repeat(MAX_SOURCE_ITEM_BYTES);
        }
        let descriptor =
            EpistemicDescriptor::from_kioku(&memory(MemoryLifecycleState::Active), &evidence);
        assert!(descriptor.validate().is_ok());
        assert!(serialized_len(&descriptor) <= MAX_DESCRIPTOR_BYTES);
    }

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
        let descriptor = EpistemicDescriptor::from_external_evidence(&submission);
        assert_eq!(descriptor.origin_class, OriginClass::Asserted);
        assert_eq!(descriptor.evidence_status, EvidenceStatus::Unknown);
        assert_eq!(descriptor.source_refs, vec!["submission-1"]);
        assert!(descriptor.validate().is_ok());
    }

    #[test]
    fn protobuf_reference_is_additive_and_round_trips_unknowns() {
        use prost::Message;
        use sekai_proto::chisei::{EpistemicDescriptor as PbDescriptor, MemoryContextReference};

        let reference = MemoryContextReference {
            memory_id: "memory-1".into(),
            memory_version: 1,
            descriptor: Some(PbDescriptor {
                contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
                origin_class: "unknown".into(),
                evidence_status: "unknown".into(),
                lifecycle_status: "unknown".into(),
                source_rows_truncated: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        let encoded = reference.encode_to_vec();
        let decoded = MemoryContextReference::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.memory_id, "memory-1");
        assert_eq!(
            decoded
                .descriptor
                .as_ref()
                .map(|descriptor| descriptor.contract_version.as_str()),
            Some(EPISTEMIC_DESCRIPTOR_VERSION)
        );

        // A legacy reference with no field 8 remains valid and decodes with an
        // absent descriptor, so old producers/clients do not need a rollout.
        let legacy = MemoryContextReference {
            memory_id: "legacy".into(),
            memory_version: 1,
            ..Default::default()
        };
        let decoded_legacy =
            MemoryContextReference::decode(legacy.encode_to_vec().as_slice()).unwrap();
        assert!(decoded_legacy.descriptor.is_none());
    }
}
