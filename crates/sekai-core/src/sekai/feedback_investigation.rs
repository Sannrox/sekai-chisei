//! Investigate recurring application observations (#1231).
//!
//! A plane-owned Action binding admits one `feedback.investigation.dispatch`
//! per new observation. The worker claims that work, gathers authorized
//! evidence, and records structured investigation, hypothesis, and finding
//! objects. Internal and malformed results never set the qualifying
//! classification that GitHub publication (#1232) consumes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, Object};
use crate::sekai::action_binding::ActionBinding;
use crate::sekai::action_effect::{
    ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED, EFFECT_STATUS_CLAIMED,
};
use crate::sekai::action_instance::STATUS_ADMITTED;
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use crate::sekai::action_work_lifecycle::{
    AckActionWork, ActionWorkLifecycle, ClaimActionWork, ClaimedActionWork,
};
use crate::sekai::feedback_package::{
    ACTION_DISPATCH, ACTION_FINDING, ACTION_HYPOTHESIS, ACTION_INVESTIGATION,
    KIND_INVESTIGATION_RESULT, KIND_OBSERVATION, PACKAGE_VERSION,
};
use crate::sekai::object_security::PrincipalPolicyContext;

pub const RUNTIME_ID: &str = "feedback-investigation";
pub const POLL_INTERVAL_SECS: u64 = 15;
pub const RECURRENCE_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
pub const MIN_RECURRING_OPERATIONS: usize = 3;
pub const CLASSIFICATION_QUALIFYING: &str = "qualifying";
pub const CLASSIFICATION_INTERNAL: &str = "internal";

const CLAIM_TTL_MS: i64 = 60_000;

/// Who the analysis, or the observation vocabulary, attributes the problem to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    Tenkai,
    Application,
    ExpectedWait,
    Cancellation,
    Inconclusive,
    Malformed,
}

/// Whether a finding may later dispatch a GitHub mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilingDecision {
    Qualifying,
    Internal,
}

impl FilingDecision {
    pub fn classification(self) -> &'static str {
        match self {
            Self::Qualifying => CLASSIFICATION_QUALIFYING,
            Self::Internal => CLASSIFICATION_INTERNAL,
        }
    }

    pub fn allows_github_dispatch(self) -> bool {
        matches!(self, Self::Qualifying)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationAnalysis {
    #[serde(default)]
    pub observed_facts: Vec<String>,
    #[serde(default)]
    pub hypotheses: Vec<String>,
    #[serde(default)]
    pub impact: String,
    pub attribution: Attribution,
    #[serde(default)]
    pub proposed_reproduction: String,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
    /// Model-proposed reproductions are not measured facts.
    #[serde(default)]
    pub independently_verified_reproduction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationView {
    pub object_id: String,
    pub created_ms: i64,
    pub problem_signature: String,
    pub occurrence_ids: Vec<String>,
    pub classification: String,
    pub disposition: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationCluster {
    pub namespace: String,
    pub trigger_id: String,
    pub signature: String,
    pub observations: Vec<ObservationView>,
    pub distinct_operations: Vec<String>,
    pub has_measured_reproduction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRequest {
    pub namespace: String,
    pub signature: String,
    pub observations: Vec<ObservationView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigateReport {
    pub filing: FilingDecision,
    pub investigation_id: String,
    pub finding_id: String,
    pub hypothesis_ids: Vec<String>,
}

#[derive(Debug)]
pub enum AnalysisError {
    BudgetExhausted,
    Malformed(String),
    Unavailable(String),
}

#[derive(Debug)]
pub enum InvestigateError {
    BudgetExhausted,
    NotDispatch,
    Internal(String),
}

pub trait FeedbackAnalyzer {
    fn analyze(&self, request: &AnalysisRequest) -> Result<InvestigationAnalysis, AnalysisError>;
}

/// Split occurrence identifiers. Replayed delivery of one id is one operation.
pub fn parse_occurrence_ids(raw: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut ids = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let id = part.trim();
        if id.is_empty() || !seen.insert(id.to_string()) {
            continue;
        }
        ids.push(id.to_string());
    }
    ids
}

pub fn observation_view(object: &Object) -> Option<ObservationView> {
    if object.kind != KIND_OBSERVATION {
        return None;
    }
    let signature = object
        .properties
        .get("problem_signature")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if signature.is_empty() {
        return None;
    }
    Some(ObservationView {
        object_id: object.id.clone(),
        created_ms: object.created,
        problem_signature: signature.into(),
        occurrence_ids: parse_occurrence_ids(
            object
                .properties
                .get("occurrence_ids")
                .map(String::as_str)
                .unwrap_or(""),
        ),
        classification: object
            .properties
            .get("classification")
            .cloned()
            .unwrap_or_default(),
        disposition: object
            .properties
            .get("disposition")
            .cloned()
            .unwrap_or_default(),
        source_evidence: object
            .properties
            .get("source_evidence")
            .cloned()
            .unwrap_or_default(),
    })
}

/// Application failures, cancellation, and expected waits are not Tenkai defects.
pub fn precludes_tenkai_defect(observation: &ObservationView) -> bool {
    let classification = observation.classification.as_str();
    if matches!(
        classification,
        "cancelled" | "blocked" | "ok" | "reconciled"
    ) {
        return true;
    }
    let signature = observation.problem_signature.as_str();
    signature_reason(signature).is_some_and(|reason| {
        matches!(
            reason,
            "product_failed"
                | "product_failed_restored"
                | "cancelled"
                | "blocked"
                | "maintenance_blocked"
                | "gate_blocked"
        )
    })
}

fn signature_reason(signature: &str) -> Option<&str> {
    signature.rsplit_once(':').map(|(_, reason)| reason)
}

pub fn cluster_from_observations(
    namespace: &str,
    trigger_id: &str,
    signature: &str,
    now_ms: i64,
    observations: Vec<ObservationView>,
    has_measured_reproduction: bool,
) -> ObservationCluster {
    let window_start = now_ms.saturating_sub(RECURRENCE_WINDOW_MS);
    let mut in_window: Vec<ObservationView> = observations
        .into_iter()
        .filter(|observation| {
            observation.problem_signature == signature && observation.created_ms >= window_start
        })
        .collect();
    in_window.sort_by(|left, right| {
        left.created_ms
            .cmp(&right.created_ms)
            .then(left.object_id.cmp(&right.object_id))
    });
    let mut seen = BTreeSet::new();
    let mut distinct_operations = Vec::new();
    for observation in &in_window {
        for occurrence in &observation.occurrence_ids {
            if seen.insert(occurrence.clone()) {
                distinct_operations.push(occurrence.clone());
            }
        }
    }
    ObservationCluster {
        namespace: namespace.into(),
        trigger_id: trigger_id.into(),
        signature: signature.into(),
        observations: in_window,
        distinct_operations,
        has_measured_reproduction,
    }
}

pub fn decide_filing(
    cluster: &ObservationCluster,
    analysis: &InvestigationAnalysis,
) -> FilingDecision {
    if matches!(
        analysis.attribution,
        Attribution::Inconclusive | Attribution::Malformed
    ) {
        return FilingDecision::Internal;
    }
    if cluster.has_measured_reproduction {
        return FilingDecision::Qualifying;
    }
    // Model-proposed steps are hypotheses, not a measured reproduction.
    if cluster.observations.iter().all(precludes_tenkai_defect) {
        return FilingDecision::Internal;
    }
    if analysis.attribution != Attribution::Tenkai {
        return FilingDecision::Internal;
    }
    if cluster.distinct_operations.len() >= MIN_RECURRING_OPERATIONS {
        FilingDecision::Qualifying
    } else {
        FilingDecision::Internal
    }
}

pub fn github_dispatch_permitted(finding: &Object) -> bool {
    finding.kind == crate::sekai::feedback_package::KIND_FINDING
        && finding.properties.get("classification").map(String::as_str)
            == Some(CLASSIFICATION_QUALIFYING)
}

pub fn analysis_system_prompt() -> &'static str {
    "You investigate Tenkai application observations. Reply with one JSON object only, no tools, no code. Keys: observed_facts (string array), hypotheses (string array), impact (string), attribution (tenkai|application|expected_wait|cancellation|inconclusive|malformed), proposed_reproduction (string), missing_evidence (string array), independently_verified_reproduction (boolean, true only for a measured reproduction you did not invent)."
}

pub fn analysis_prompt(request: &AnalysisRequest) -> String {
    let mut body = String::from("Observations:\n");
    for observation in &request.observations {
        body.push_str(&format!(
            "- id={} signature={} occurrences={} classification={} disposition={}\n",
            observation.object_id,
            observation.problem_signature,
            observation.occurrence_ids.join(","),
            observation.classification,
            observation.disposition
        ));
    }
    body
}

pub fn parse_model_analysis_json(raw: &str) -> Result<InvestigationAnalysis, AnalysisError> {
    let json = extract_json_object(raw)
        .ok_or_else(|| AnalysisError::Malformed("model result is not a JSON object".into()))?;
    serde_json::from_str(&json).map_err(|error| AnalysisError::Malformed(error.to_string()))
}

fn extract_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    if end < start {
        return None;
    }
    Some(raw[start..=end].to_string())
}

pub fn investigation_bindings(bindings: &[ActionBinding]) -> Vec<ActionBinding> {
    bindings
        .iter()
        .filter(|binding| {
            binding.enabled
                && binding.kind == KIND_OBSERVATION
                && binding.type_id == ACTION_DISPATCH
                && binding.version == PACKAGE_VERSION
        })
        .cloned()
        .collect()
}

pub fn investigation_in_flight(
    db: &RuntimeDb,
    namespace: &str,
    now_ms: i64,
) -> Result<bool, String> {
    let instances =
        db.list_action_instances(namespace, Some(ACTION_DISPATCH), Some(STATUS_ADMITTED), 64)?;
    for instance in instances {
        for effect in db.list_action_effects_for_instance(&instance.instance_id)? {
            if effect.status == EFFECT_STATUS_CLAIMED && effect.claim_expires_at_ms > now_ms {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn claim_next_dispatch(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<Option<ClaimedActionWork>, InvestigateError> {
    if investigation_in_flight(db, namespace, now_ms).map_err(InvestigateError::Internal)? {
        return Ok(None);
    }
    let claimable = db
        .list_claimable_action_work(namespace, Some(RUNTIME_ID), now_ms, 16)
        .map_err(InvestigateError::Internal)?;
    for effect in claimable {
        let Some(instance) = db
            .get_action_instance(&effect.instance_id)
            .map_err(InvestigateError::Internal)?
        else {
            continue;
        };
        if instance.type_id != ACTION_DISPATCH {
            continue;
        }
        let claimed = ActionWorkLifecycle::new(db)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: RUNTIME_ID,
                    request_id: &format!("feedback-claim-{}", effect.effect_id),
                    ttl_ms: CLAIM_TTL_MS,
                },
                actor,
                now_ms,
            )
            .map_err(|error| InvestigateError::Internal(format!("{error:?}")))?;
        return Ok(Some(claimed));
    }
    Ok(None)
}

pub fn ack_investigation(
    db: &RuntimeDb,
    claimed: &ClaimedActionWork,
    actor: &str,
    outcome: &str,
    reason: &str,
    now_ms: i64,
) -> Result<(), InvestigateError> {
    ActionWorkLifecycle::new(db)
        .ack(
            AckActionWork {
                effect_id: &claimed.effect.effect_id,
                runtime_id: RUNTIME_ID,
                claim_generation: claimed.effect.claim_generation,
                fencing_token: &claimed.effect.claim_fencing_token,
                outcome,
                reason,
                request_id: &format!("feedback-claim-{}", claimed.effect.effect_id),
                checkpoint_store_id: "",
                checkpoint_ref: "",
                checkpoint_digest: "",
                artifact_json: "",
            },
            actor,
            now_ms,
        )
        .map(|_| ())
        .map_err(|error| InvestigateError::Internal(format!("{error:?}")))
}

pub fn gather_cluster(
    db: &RuntimeDb,
    namespace: &str,
    observation_id: &str,
    now_ms: i64,
) -> Result<ObservationCluster, InvestigateError> {
    let stored = db
        .get_object(observation_id)
        .map_err(InvestigateError::Internal)?
        .ok_or_else(|| {
            InvestigateError::Internal(format!("observation {observation_id} not found"))
        })?;
    if stored.namespace != namespace || stored.kind != KIND_OBSERVATION {
        return Err(InvestigateError::Internal(
            "dispatch target is not an observation in the work namespace".into(),
        ));
    }
    let visible = db
        .project_object_property_grants(stored)
        .map_err(InvestigateError::Internal)?;
    let trigger = observation_view(&visible).ok_or_else(|| {
        InvestigateError::Internal("observation signature is hidden or missing".into())
    })?;
    let listed = db
        .list_objects(&ListFilter {
            kind: Some(KIND_OBSERVATION.into()),
            namespace: Some(namespace.into()),
            limit: 256,
            ..ListFilter::default()
        })
        .map_err(InvestigateError::Internal)?;
    let mut views = Vec::new();
    for object in listed {
        let projected = db
            .project_object_property_grants(object)
            .map_err(InvestigateError::Internal)?;
        if let Some(view) = observation_view(&projected)
            && view.problem_signature == trigger.problem_signature
        {
            views.push(view);
        }
    }
    let measured = namespace_has_measured_reproduction(db, namespace, &trigger.problem_signature)?;
    Ok(cluster_from_observations(
        namespace,
        observation_id,
        &trigger.problem_signature,
        now_ms,
        views,
        measured,
    ))
}

fn namespace_has_measured_reproduction(
    db: &RuntimeDb,
    namespace: &str,
    signature: &str,
) -> Result<bool, InvestigateError> {
    let results = db
        .list_objects(&ListFilter {
            kind: Some(KIND_INVESTIGATION_RESULT.into()),
            namespace: Some(namespace.into()),
            limit: 256,
            ..ListFilter::default()
        })
        .map_err(InvestigateError::Internal)?;
    for object in results {
        if object.properties.get("measured").map(String::as_str) != Some("true") {
            continue;
        }
        let Some(observation_id) = object.properties.get("observation_id") else {
            continue;
        };
        let Some(observation) = db
            .get_object(observation_id)
            .map_err(InvestigateError::Internal)?
        else {
            continue;
        };
        if observation
            .properties
            .get("problem_signature")
            .map(String::as_str)
            == Some(signature)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn investigate_claimed(
    db: &RuntimeDb,
    claimed: &ClaimedActionWork,
    analyzer: &dyn FeedbackAnalyzer,
    actor: &str,
    now_ms: i64,
) -> Result<InvestigateReport, InvestigateError> {
    let instance = db
        .get_action_instance(&claimed.effect.instance_id)
        .map_err(InvestigateError::Internal)?
        .ok_or_else(|| InvestigateError::Internal("claimed instance is gone".into()))?;
    if instance.type_id != ACTION_DISPATCH {
        return Err(InvestigateError::NotDispatch);
    }
    let parameters: HashMap<String, serde_json::Value> =
        serde_json::from_str(&instance.parameters_json)
            .map_err(|error| InvestigateError::Internal(error.to_string()))?;
    let observation_id = parameters
        .get("observation_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| InvestigateError::Internal("dispatch is missing observation_id".into()))?
        .to_string();
    let cluster = gather_cluster(db, &instance.namespace, &observation_id, now_ms)?;
    let request = AnalysisRequest {
        namespace: cluster.namespace.clone(),
        signature: cluster.signature.clone(),
        observations: cluster.observations.clone(),
    };
    let analysis = match analyzer.analyze(&request) {
        Ok(analysis) => analysis,
        Err(AnalysisError::BudgetExhausted) => return Err(InvestigateError::BudgetExhausted),
        Err(AnalysisError::Malformed(_)) => InvestigationAnalysis {
            attribution: Attribution::Malformed,
            ..empty_analysis()
        },
        Err(AnalysisError::Unavailable(_)) => InvestigationAnalysis {
            attribution: Attribution::Inconclusive,
            ..empty_analysis()
        },
    };
    let filing = decide_filing(&cluster, &analysis);
    write_records(db, actor, &cluster, &analysis, filing, now_ms)
}

pub fn empty_analysis() -> InvestigationAnalysis {
    InvestigationAnalysis {
        observed_facts: Vec::new(),
        hypotheses: Vec::new(),
        impact: String::new(),
        attribution: Attribution::Inconclusive,
        proposed_reproduction: String::new(),
        missing_evidence: Vec::new(),
        independently_verified_reproduction: false,
    }
}

/// Persist investigation, hypothesis, and finding objects for a cluster.
pub fn record_investigation(
    db: &RuntimeDb,
    cluster: &ObservationCluster,
    analysis: &InvestigationAnalysis,
    actor: &str,
    now_ms: i64,
) -> Result<InvestigateReport, InvestigateError> {
    write_records(
        db,
        actor,
        cluster,
        analysis,
        decide_filing(cluster, analysis),
        now_ms,
    )
}

fn write_records(
    db: &RuntimeDb,
    actor: &str,
    cluster: &ObservationCluster,
    analysis: &InvestigationAnalysis,
    filing: FilingDecision,
    now_ms: i64,
) -> Result<InvestigateReport, InvestigateError> {
    let key = cluster_key(cluster);
    let investigation_id = format!("fb-inv-{key}");
    let finding_id = format!("fb-find-{key}");
    let outcome = serde_json::json!({
        "observed_facts": analysis.observed_facts,
        "impact": analysis.impact,
        "attribution": analysis.attribution,
        "proposed_reproduction": analysis.proposed_reproduction,
        "missing_evidence": analysis.missing_evidence,
        "filing": filing,
    });
    admit(
        db,
        actor,
        &cluster.namespace,
        ACTION_INVESTIGATION,
        serde_json::json!({
            "object_id": investigation_id,
            "name": cluster.signature,
            "observation_id": cluster.trigger_id,
            "outcome": outcome.to_string(),
            "measured": analysis.independently_verified_reproduction,
        }),
        &format!("feedback:inv:{key}"),
        now_ms,
    )?;
    let mut hypothesis_ids = Vec::new();
    for (index, statement) in analysis.hypotheses.iter().enumerate() {
        let hypothesis_id = format!("fb-hyp-{key}-{index}");
        admit(
            db,
            actor,
            &cluster.namespace,
            ACTION_HYPOTHESIS,
            serde_json::json!({
                "object_id": hypothesis_id,
                "name": cluster.signature,
                "observation_id": cluster.trigger_id,
                "statement": statement,
            }),
            &format!("feedback:hyp:{key}:{index}"),
            now_ms,
        )?;
        hypothesis_ids.push(hypothesis_id);
    }
    admit(
        db,
        actor,
        &cluster.namespace,
        ACTION_FINDING,
        serde_json::json!({
            "object_id": finding_id,
            "name": cluster.signature,
            "observation_id": cluster.trigger_id,
            "statement": filing_statement(cluster, analysis, filing),
            "classification": filing.classification(),
        }),
        &format!("feedback:find:{key}"),
        now_ms,
    )?;
    Ok(InvestigateReport {
        filing,
        investigation_id,
        finding_id,
        hypothesis_ids,
    })
}

fn filing_statement(
    cluster: &ObservationCluster,
    analysis: &InvestigationAnalysis,
    filing: FilingDecision,
) -> String {
    format!(
        "filing={} attribution={:?} operations={} impact={}",
        filing.classification(),
        analysis.attribution,
        cluster.distinct_operations.len(),
        analysis.impact
    )
}

fn cluster_key(cluster: &ObservationCluster) -> String {
    let mut material = cluster.namespace.clone();
    material.push('\0');
    material.push_str(&cluster.signature);
    material.push('\0');
    material.push_str(&cluster.distinct_operations.join("\0"));
    let digest = format!("{:x}", Sha256::digest(material.as_bytes()));
    digest[..16].to_string()
}

fn admit(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    type_id: &str,
    parameters: serde_json::Value,
    idempotency_key: &str,
    now_ms: i64,
) -> Result<(), InvestigateError> {
    ActionInstanceAdmission::new(db, None)
        .admit(
            ActionInstanceAdmissionRequest {
                agent_turn: None,
                namespace: namespace.into(),
                type_id: type_id.into(),
                version: PACKAGE_VERSION.into(),
                parameters_json: parameters.to_string(),
                idempotency_key: idempotency_key.into(),
                evidence_submission_ids: Vec::new(),
                request_id: String::new(),
                ontology_digest: String::new(),
                autonomous_envelope_id: String::new(),
                policy_context: PrincipalPolicyContext::default(),
                delegating_actor: None,
                budget_already_reserved: false,
                resource_tenant: String::new(),
                binding_markings: Vec::new(),
                source_object_id: String::new(),
                marking_gate: Default::default(),
                expected_object_revision: String::new(),
                offline: None,
            },
            actor,
            now_ms,
        )
        .map(|_| ())
        .map_err(|error| InvestigateError::Internal(format!("{error:?}")))
}

pub fn dispatch_parameters(observation_id: &str) -> serde_json::Value {
    serde_json::json!({
        "observation_id": observation_id,
        "runtime": RUNTIME_ID,
    })
}

pub fn ack_outcomes() -> (&'static str, &'static str) {
    (ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED)
}

/// Bindings that fire investigation dispatch from observation creates.
pub fn investigation_binding(namespace: &str, binding_id: &str, run_as: &str) -> ActionBinding {
    use crate::sekai::action_binding::{ACTION_BINDING_CONTRACT, ParameterSource};
    use crate::sekai::object_change_subscription::OP_CREATE;
    use std::collections::BTreeMap;
    ActionBinding {
        contract_version: ACTION_BINDING_CONTRACT.into(),
        binding_id: binding_id.into(),
        namespace: namespace.into(),
        kind: KIND_OBSERVATION.into(),
        property_filters: Vec::new(),
        ops: vec![OP_CREATE.into()],
        type_id: ACTION_DISPATCH.into(),
        version: PACKAGE_VERSION.into(),
        run_as: run_as.into(),
        parameters: BTreeMap::from([
            ("observation_id".into(), ParameterSource::ObjectId),
            (
                "runtime".into(),
                ParameterSource::Constant(RUNTIME_ID.into()),
            ),
        ]),
        markings: Vec::new(),
        enabled: true,
        revision: 0,
        created_by: String::new(),
        updated_at_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::action_effect::ActionEffect;
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceEnvelope, EvidenceIntent, EvidenceSignal,
        EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
    use crate::sekai::evidence_store::{EvidenceProducerCapability, canonical_content_digest};
    use crate::sekai::feedback_package::{
        ACTION_OBSERVATION, EVIDENCE_SCHEMA_VERSION, EVIDENCE_TYPE, KIND_FINDING, KIND_HYPOTHESIS,
        install,
    };
    use serde_json::json;
    use std::sync::Arc;

    const NAMESPACE: &str = "ops";
    const ACTOR: &str = "reviewer";

    struct FixedAnalyzer(InvestigationAnalysis);
    impl FeedbackAnalyzer for FixedAnalyzer {
        fn analyze(&self, _: &AnalysisRequest) -> Result<InvestigationAnalysis, AnalysisError> {
            Ok(self.0.clone())
        }
    }

    struct FailAnalyzer(AnalysisError);
    impl FeedbackAnalyzer for FailAnalyzer {
        fn analyze(&self, _: &AnalysisRequest) -> Result<InvestigationAnalysis, AnalysisError> {
            match &self.0 {
                AnalysisError::BudgetExhausted => Err(AnalysisError::BudgetExhausted),
                AnalysisError::Malformed(message) => Err(AnalysisError::Malformed(message.clone())),
                AnalysisError::Unavailable(message) => {
                    Err(AnalysisError::Unavailable(message.clone()))
                }
            }
        }
    }

    fn db() -> RuntimeDb {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();
        runtime
    }

    fn tenkai_analysis() -> InvestigationAnalysis {
        InvestigationAnalysis {
            observed_facts: vec!["step failed in the controller".into()],
            hypotheses: vec!["lease fencing dropped".into()],
            impact: "apply cannot finish".into(),
            attribution: Attribution::Tenkai,
            proposed_reproduction: "replay the same plan".into(),
            missing_evidence: Vec::new(),
            independently_verified_reproduction: true,
        }
    }

    fn producer() -> EvidenceProducerCapability {
        EvidenceProducerCapability {
            producer_identity: "producer:feedback".into(),
            config_version: 1,
            source_types: vec!["feedback_source".into()],
            source_instances: vec!["feedback:checks".into()],
            namespaces: vec![NAMESPACE.into()],
            evidence_types: vec![EVIDENCE_TYPE.into()],
            target_kinds: vec![KIND_OBSERVATION.into()],
            classification_ceiling: crate::sekai::evidence::EvidenceClassification::Confidential,
            allowed_intents: vec![EvidenceIntent::Upsert],
            allow_operation_attachment: true,
            replay_window_ms: 10_000,
            max_clock_skew_ms: 1_000,
            max_payload_bytes: 4_096,
            max_relationships: 4,
            rate_limit_per_minute: 20,
            max_retained_submissions: 100,
            revoked: false,
        }
    }

    fn envelope(
        external_id: &str,
        signature: &str,
        occurrence: &str,
        classification: &str,
    ) -> EvidenceEnvelope {
        let content = json!({
            "problem_signature": signature,
            "occurrence_ids": occurrence,
            "classification": classification,
            "disposition": "open"
        });
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "feedback_source".into(),
            source_instance: "feedback:checks".into(),
            source_record_id: external_id.into(),
            source_version: "attempt-1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: NAMESPACE.into(),
                object_external_id: external_id.into(),
                object_kind: KIND_OBSERVATION.into(),
            },
            evidence_type: EVIDENCE_TYPE.into(),
            signal: EvidenceSignal::OperationalHealth,
            schema_id: EVIDENCE_TYPE.into(),
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: 1_000,
            collected_at_ms: 1_010,
            expires_at_ms: Some(60_000_000),
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: "producer:feedback".into(),
            confidence_bps: 9_000,
            classification: crate::sekai::evidence::EvidenceClassification::Internal,
            provenance: Default::default(),
            idempotency_key: format!("delivery-{external_id}"),
            intent: EvidenceIntent::Upsert,
            causality: None,
        }
    }

    fn record_observation(
        runtime: &RuntimeDb,
        id: &str,
        signature: &str,
        occurrence: &str,
        classification: &str,
        created_ms: i64,
    ) {
        let admission = EvidenceAdmissionLifecycle::new(runtime)
            .admit(
                &envelope(id, signature, occurrence, classification),
                "producer:feedback",
                created_ms,
            )
            .unwrap();
        let evidence_id = admission.submission.id.clone();
        ActionInstanceAdmission::new(runtime, None)
            .admit(
                ActionInstanceAdmissionRequest {
                    agent_turn: None,
                    namespace: NAMESPACE.into(),
                    type_id: ACTION_OBSERVATION.into(),
                    version: PACKAGE_VERSION.into(),
                    parameters_json: json!({
                        "object_id": id,
                        "name": signature,
                        "source_evidence": evidence_id,
                        "problem_signature": signature,
                        "occurrence_ids": occurrence,
                        "classification": classification,
                        "disposition": "open"
                    })
                    .to_string(),
                    idempotency_key: format!("obs-{id}"),
                    evidence_submission_ids: vec![evidence_id],
                    request_id: String::new(),
                    ontology_digest: String::new(),
                    autonomous_envelope_id: String::new(),
                    policy_context: PrincipalPolicyContext::default(),
                    delegating_actor: None,
                    budget_already_reserved: false,
                    resource_tenant: String::new(),
                    binding_markings: Vec::new(),
                    source_object_id: String::new(),
                    marking_gate: Default::default(),
                    expected_object_revision: String::new(),
                    offline: None,
                },
                ACTOR,
                created_ms,
            )
            .unwrap();
        let mut stored = runtime.get_object(id).unwrap().unwrap();
        stored.created = created_ms;
        stored.updated = created_ms;
        runtime.update_object(&stored).unwrap();
    }

    fn admit_dispatch(
        runtime: &RuntimeDb,
        observation_id: &str,
        key: &str,
        now_ms: i64,
    ) -> ActionEffect {
        let outcome = ActionInstanceAdmission::new(runtime, None)
            .admit(
                ActionInstanceAdmissionRequest {
                    agent_turn: None,
                    namespace: NAMESPACE.into(),
                    type_id: ACTION_DISPATCH.into(),
                    version: PACKAGE_VERSION.into(),
                    parameters_json: dispatch_parameters(observation_id).to_string(),
                    idempotency_key: key.into(),
                    evidence_submission_ids: Vec::new(),
                    request_id: String::new(),
                    ontology_digest: String::new(),
                    autonomous_envelope_id: String::new(),
                    policy_context: PrincipalPolicyContext::default(),
                    delegating_actor: None,
                    budget_already_reserved: false,
                    resource_tenant: String::new(),
                    binding_markings: Vec::new(),
                    source_object_id: String::new(),
                    marking_gate: Default::default(),
                    expected_object_revision: String::new(),
                    offline: None,
                },
                ACTOR,
                now_ms,
            )
            .unwrap();
        runtime
            .list_action_effects_for_instance(&outcome.instance.instance_id)
            .unwrap()
            .into_iter()
            .find(|effect| effect.kind == "runtime_dispatch")
            .expect("dispatch effect")
    }

    fn view(
        id: &str,
        signature: &str,
        occurrence: &str,
        classification: &str,
        created_ms: i64,
    ) -> ObservationView {
        ObservationView {
            object_id: id.into(),
            created_ms,
            problem_signature: signature.into(),
            occurrence_ids: parse_occurrence_ids(occurrence),
            classification: classification.into(),
            disposition: "open".into(),
            source_evidence: String::new(),
        }
    }

    #[test]
    fn investigation_polls_every_15_seconds() {
        assert_eq!(POLL_INTERVAL_SECS, 15);
    }

    #[test]
    fn replayed_occurrence_ids_are_one_operation() {
        assert_eq!(
            parse_occurrence_ids("occ-1,occ-1 occ-2"),
            ["occ-1", "occ-2"]
        );
    }

    #[test]
    fn three_tenkai_operations_in_24h_qualify() {
        let cluster = cluster_from_observations(
            NAMESPACE,
            "o-3",
            "api:tenkai_failed",
            10_000,
            vec![
                view("o-1", "api:tenkai_failed", "op-1", "defect", 1_000),
                view("o-2", "api:tenkai_failed", "op-2", "defect", 2_000),
                view("o-3", "api:tenkai_failed", "op-3", "defect", 3_000),
            ],
            false,
        );
        assert_eq!(cluster.distinct_operations.len(), 3);
        assert_eq!(
            decide_filing(&cluster, &tenkai_analysis()),
            FilingDecision::Qualifying
        );
    }

    #[test]
    fn a_replayed_observation_is_not_recurrence() {
        let cluster = cluster_from_observations(
            NAMESPACE,
            "o-2",
            "api:tenkai_failed",
            10_000,
            vec![
                view("o-1", "api:tenkai_failed", "op-1", "defect", 1_000),
                view("o-2", "api:tenkai_failed", "op-1", "defect", 2_000),
            ],
            false,
        );
        assert_eq!(cluster.distinct_operations, ["op-1"]);
        assert_eq!(
            decide_filing(&cluster, &tenkai_analysis()),
            FilingDecision::Internal
        );
    }

    #[test]
    fn application_cancellation_and_waits_do_not_qualify() {
        let analysis = tenkai_analysis();
        for (signature, classification) in [
            ("api:product_failed", "defect"),
            ("api:cancelled", "cancelled"),
            ("api:maintenance_blocked", "blocked"),
        ] {
            let cluster = cluster_from_observations(
                NAMESPACE,
                "o-3",
                signature,
                10_000,
                vec![
                    view("o-1", signature, "op-1", classification, 1_000),
                    view("o-2", signature, "op-2", classification, 2_000),
                    view("o-3", signature, "op-3", classification, 3_000),
                ],
                false,
            );
            assert_eq!(
                decide_filing(&cluster, &analysis),
                FilingDecision::Internal,
                "{signature}"
            );
        }
    }

    #[test]
    fn model_proposed_reproduction_does_not_qualify() {
        let cluster = cluster_from_observations(
            NAMESPACE,
            "o-1",
            "api:tenkai_failed",
            10_000,
            vec![view("o-1", "api:tenkai_failed", "op-1", "defect", 1_000)],
            false,
        );
        assert_eq!(
            decide_filing(&cluster, &tenkai_analysis()),
            FilingDecision::Internal
        );
    }

    #[test]
    fn a_measured_reproduction_qualifies() {
        let cluster = cluster_from_observations(
            NAMESPACE,
            "o-1",
            "api:tenkai_failed",
            10_000,
            vec![view("o-1", "api:tenkai_failed", "op-1", "defect", 1_000)],
            true,
        );
        assert_eq!(
            decide_filing(&cluster, &tenkai_analysis()),
            FilingDecision::Qualifying
        );
    }

    #[test]
    fn inconclusive_and_malformed_stay_internal() {
        let cluster = cluster_from_observations(
            NAMESPACE,
            "o-3",
            "api:tenkai_failed",
            10_000,
            vec![
                view("o-1", "api:tenkai_failed", "op-1", "defect", 1_000),
                view("o-2", "api:tenkai_failed", "op-2", "defect", 2_000),
                view("o-3", "api:tenkai_failed", "op-3", "defect", 3_000),
            ],
            false,
        );
        for attribution in [Attribution::Inconclusive, Attribution::Malformed] {
            let mut analysis = tenkai_analysis();
            analysis.attribution = attribution;
            let filing = decide_filing(&cluster, &analysis);
            assert_eq!(filing, FilingDecision::Internal);
            assert!(!filing.allows_github_dispatch());
        }
    }

    #[test]
    fn observations_outside_24h_do_not_count() {
        let cluster = cluster_from_observations(
            NAMESPACE,
            "o-3",
            "api:tenkai_failed",
            RECURRENCE_WINDOW_MS + 5_000,
            vec![
                view("o-1", "api:tenkai_failed", "op-1", "defect", 1_000),
                view(
                    "o-2",
                    "api:tenkai_failed",
                    "op-2",
                    "defect",
                    RECURRENCE_WINDOW_MS + 2_000,
                ),
                view(
                    "o-3",
                    "api:tenkai_failed",
                    "op-3",
                    "defect",
                    RECURRENCE_WINDOW_MS + 3_000,
                ),
            ],
            false,
        );
        assert_eq!(cluster.distinct_operations.len(), 2);
    }

    #[test]
    fn hidden_occurrence_ids_are_not_counted() {
        let mut hidden = view("o-2", "api:tenkai_failed", "op-2", "defect", 2_000);
        hidden.occurrence_ids.clear();
        let cluster = cluster_from_observations(
            NAMESPACE,
            "o-2",
            "api:tenkai_failed",
            10_000,
            vec![
                view("o-1", "api:tenkai_failed", "op-1", "defect", 1_000),
                hidden,
                view("o-3", "api:tenkai_failed", "op-3", "defect", 3_000),
            ],
            false,
        );
        assert_eq!(cluster.distinct_operations, ["op-1", "op-3"]);
    }

    #[test]
    fn disabled_bindings_are_not_polled() {
        let mut binding = investigation_binding(NAMESPACE, "investigate", ACTOR);
        binding.enabled = false;
        assert!(investigation_bindings(&[binding]).is_empty());
        assert_eq!(
            investigation_bindings(&[investigation_binding(NAMESPACE, "investigate", ACTOR)]).len(),
            1
        );
    }

    #[test]
    fn malformed_model_json_is_internal() {
        assert!(parse_model_analysis_json("not json").is_err());
        let parsed = parse_model_analysis_json(
            "here is json {\"observed_facts\":[],\"hypotheses\":[],\"impact\":\"\",\"attribution\":\"tenkai\",\"proposed_reproduction\":\"\",\"missing_evidence\":[]}",
        )
        .unwrap();
        assert_eq!(parsed.attribution, Attribution::Tenkai);
    }

    #[test]
    fn three_tenkai_observations_write_a_qualifying_finding() {
        let runtime = db();
        let now = 10_000;
        record_observation(
            &runtime,
            "o-1",
            "api:tenkai_failed",
            "op-1",
            "defect",
            1_000,
        );
        record_observation(
            &runtime,
            "o-2",
            "api:tenkai_failed",
            "op-2",
            "defect",
            2_000,
        );
        record_observation(
            &runtime,
            "o-3",
            "api:tenkai_failed",
            "op-3",
            "defect",
            3_000,
        );
        let effect = admit_dispatch(&runtime, "o-3", "dispatch-3", now);
        let claimed = ActionWorkLifecycle::new(&runtime)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: RUNTIME_ID,
                    request_id: &format!("feedback-claim-{}", effect.effect_id),
                    ttl_ms: CLAIM_TTL_MS,
                },
                ACTOR,
                now,
            )
            .unwrap();
        let report = investigate_claimed(
            &runtime,
            &claimed,
            &FixedAnalyzer(tenkai_analysis()),
            ACTOR,
            now,
        )
        .unwrap();
        assert_eq!(report.filing, FilingDecision::Qualifying);
        let finding = runtime.get_object(&report.finding_id).unwrap().unwrap();
        assert_eq!(finding.kind, KIND_FINDING);
        assert!(github_dispatch_permitted(&finding));
        let investigation = runtime
            .get_object(&report.investigation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            investigation.properties.get("measured").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            runtime
                .get_object(&report.hypothesis_ids[0])
                .unwrap()
                .unwrap()
                .kind,
            KIND_HYPOTHESIS
        );
        ack_investigation(&runtime, &claimed, ACTOR, ACK_OUTCOME_COMPLETED, "", now).unwrap();
    }

    #[test]
    fn budget_exhaustion_writes_nothing() {
        let runtime = db();
        record_observation(
            &runtime,
            "o-1",
            "api:tenkai_failed",
            "op-1",
            "defect",
            1_000,
        );
        let effect = admit_dispatch(&runtime, "o-1", "dispatch-1", 2_000);
        let claimed = ActionWorkLifecycle::new(&runtime)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: RUNTIME_ID,
                    request_id: &format!("feedback-claim-{}", effect.effect_id),
                    ttl_ms: CLAIM_TTL_MS,
                },
                ACTOR,
                2_000,
            )
            .unwrap();
        let error = investigate_claimed(
            &runtime,
            &claimed,
            &FailAnalyzer(AnalysisError::BudgetExhausted),
            ACTOR,
            2_000,
        )
        .unwrap_err();
        assert!(matches!(error, InvestigateError::BudgetExhausted));
        let findings = runtime
            .list_objects(&ListFilter {
                kind: Some(KIND_FINDING.into()),
                namespace: Some(NAMESPACE.into()),
                limit: 32,
                ..ListFilter::default()
            })
            .unwrap();
        assert!(findings.is_empty());
        ack_investigation(
            &runtime,
            &claimed,
            ACTOR,
            ACK_OUTCOME_FAILED,
            "budget_exhausted",
            2_000,
        )
        .unwrap();
    }

    #[test]
    fn restart_replays_the_same_finding() {
        let runtime = db();
        record_observation(
            &runtime,
            "o-1",
            "api:tenkai_failed",
            "op-1",
            "defect",
            1_000,
        );
        record_observation(
            &runtime,
            "o-2",
            "api:tenkai_failed",
            "op-2",
            "defect",
            2_000,
        );
        record_observation(
            &runtime,
            "o-3",
            "api:tenkai_failed",
            "op-3",
            "defect",
            3_000,
        );
        let effect = admit_dispatch(&runtime, "o-3", "dispatch-3", 4_000);
        let first = ActionWorkLifecycle::new(&runtime)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: RUNTIME_ID,
                    request_id: &format!("feedback-claim-{}", effect.effect_id),
                    ttl_ms: 10,
                },
                ACTOR,
                4_000,
            )
            .unwrap();
        let first_report = investigate_claimed(
            &runtime,
            &first,
            &FixedAnalyzer(tenkai_analysis()),
            ACTOR,
            4_000,
        )
        .unwrap();
        let second = ActionWorkLifecycle::new(&runtime)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: RUNTIME_ID,
                    request_id: "other-runtime-claim",
                    ttl_ms: CLAIM_TTL_MS,
                },
                ACTOR,
                4_020,
            )
            .unwrap();
        let second_report = investigate_claimed(
            &runtime,
            &second,
            &FixedAnalyzer(tenkai_analysis()),
            ACTOR,
            4_020,
        )
        .unwrap();
        assert_eq!(first_report.finding_id, second_report.finding_id);
        let findings = runtime
            .list_objects(&ListFilter {
                kind: Some(KIND_FINDING.into()),
                namespace: Some(NAMESPACE.into()),
                limit: 32,
                ..ListFilter::default()
            })
            .unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn one_live_claim_blocks_a_second_investigation() {
        let runtime = db();
        record_observation(
            &runtime,
            "o-1",
            "api:tenkai_failed",
            "op-1",
            "defect",
            1_000,
        );
        record_observation(
            &runtime,
            "o-2",
            "api:tenkai_failed",
            "op-2",
            "defect",
            2_000,
        );
        admit_dispatch(&runtime, "o-1", "dispatch-1", 3_000);
        admit_dispatch(&runtime, "o-2", "dispatch-2", 3_100);
        let first = claim_next_dispatch(&runtime, NAMESPACE, ACTOR, 3_200)
            .unwrap()
            .expect("first claim");
        assert!(investigation_in_flight(&runtime, NAMESPACE, 3_200).unwrap());
        assert!(
            claim_next_dispatch(&runtime, NAMESPACE, ACTOR, 3_200)
                .unwrap()
                .is_none()
        );
        ack_investigation(&runtime, &first, ACTOR, ACK_OUTCOME_COMPLETED, "", 3_200).unwrap();
        assert!(!investigation_in_flight(&runtime, NAMESPACE, 3_200).unwrap());
    }

    #[test]
    fn file_sqlite_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let first = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap()));
        install(&first, NAMESPACE, ACTOR, 1_000).unwrap();
        first.upsert_evidence_producer(&producer(), 1_000).unwrap();
        record_observation(&first, "o-1", "api:tenkai_failed", "op-1", "defect", 1_000);
        record_observation(&first, "o-2", "api:tenkai_failed", "op-2", "defect", 2_000);
        record_observation(&first, "o-3", "api:tenkai_failed", "op-3", "defect", 3_000);
        let effect = admit_dispatch(&first, "o-3", "dispatch-3", 4_000);
        drop(first);
        let second = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap()));
        let claimed = ActionWorkLifecycle::new(&second)
            .claim(
                ClaimActionWork {
                    effect_id: &effect.effect_id,
                    runtime_id: RUNTIME_ID,
                    request_id: &format!("feedback-claim-{}", effect.effect_id),
                    ttl_ms: CLAIM_TTL_MS,
                },
                ACTOR,
                5_000,
            )
            .unwrap();
        let report = investigate_claimed(
            &second,
            &claimed,
            &FixedAnalyzer(tenkai_analysis()),
            ACTOR,
            5_000,
        )
        .unwrap();
        assert_eq!(report.filing, FilingDecision::Qualifying);
    }
}
