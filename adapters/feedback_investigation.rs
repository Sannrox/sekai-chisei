//! Feedback investigation runtime (#1231, out of the plane).
//!
//! A runtime outside the plane that investigates recurring feedback
//! observations through public RPCs only:
//!
//! 1. `RunActionBinding` turns new observations into
//!    `feedback.investigation.dispatch` work.
//! 2. `ListClaimableActionWork` and `ClaimActionWork` take one fenced claim.
//!    Concurrent runtimes never hold the same dispatch.
//! 3. `ListObjects` gathers the same-signature cluster in the recurrence window.
//! 4. One model call per (namespace, signature, window bucket) through
//!    `PlanExecution` and `ExecutePlanStream`. Later dispatches in the bucket
//!    reuse the stored analysis and only re-decide filing.
//! 5. `SubmitActionInstance` records investigation, hypothesis, and finding
//!    objects, then `AckActionWork` completes the claim.
//!
//! The runtime authenticates as [`INVESTIGATION_RUNTIME`]; the plane stamps
//! findings it records so publication can tell them from writer-submitted
//! ones. Internal and malformed results never set the qualifying
//! classification. The claim, list, and binding RPCs are experimental: the
//! plane needs `SEKAI_EXPERIMENTAL_RPCS=1`. Every write is idempotent by key,
//! so a crash before the ack replays into the same objects.

use std::collections::BTreeSet;

use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::chisei::chisei_service_server::ChiseiService;
use sekai_chisei::grpc::pb::chisei::{ExecutePlanRequest, ExecutionInput, PlanExecutionRequest};
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    AckActionWorkRequest, ActionEffect, ClaimActionWorkRequest, GetActionInstanceRequest,
    GetObjectRequest, ListClaimableActionWorkRequest, ListFilter, ListObjectsRequest, Object,
    PropertyFilter, RunActionBindingRequest, SubmitActionInstanceRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::feedback_package::{
    ACTION_DISPATCH, ACTION_FINDING, ACTION_HYPOTHESIS, ACTION_INVESTIGATION,
    INVESTIGATION_RUNTIME, KIND_FINDING, KIND_INVESTIGATION_RESULT, KIND_OBSERVATION,
    OUTCOME_QUALITY_EVALUATION, PACKAGE_VERSION, PROPERTY_RECORDED_BY,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_stream::StreamExt;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request, Status};

pub const RECURRENCE_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
pub const MIN_RECURRING_OPERATIONS: usize = 3;
pub const CLASSIFICATION_QUALIFYING: &str = "qualifying";
pub const CLASSIFICATION_INTERNAL: &str = "internal";
/// The prompt lists at most this many observations, newest first, plus counts.
pub const PROMPT_OBSERVATION_CAP: usize = 32;

const CLAIM_TTL_MS: i64 = 60_000;
const CLAIMABLE_PAGE: u32 = 16;
const LIST_PAGE: i32 = 256;
const BINDING_RUN_LIMIT: i32 = 32;
const ACK_COMPLETED: &str = "completed";
const ACK_FAILED: &str = "failed";

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

/// Whether a finding may later be published.
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

impl InvestigationAnalysis {
    pub fn empty(attribution: Attribution) -> Self {
        Self {
            observed_facts: Vec::new(),
            hypotheses: Vec::new(),
            impact: String::new(),
            attribution,
            proposed_reproduction: String::new(),
            missing_evidence: Vec::new(),
            independently_verified_reproduction: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationView {
    pub object_id: String,
    pub created_ms: i64,
    pub problem_signature: String,
    pub occurrence_ids: Vec<String>,
    pub classification: String,
    pub disposition: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationCluster {
    pub namespace: String,
    pub trigger_id: String,
    pub signature: String,
    /// Oldest first.
    pub observations: Vec<ObservationView>,
    pub distinct_operations: Vec<String>,
    pub has_measured_reproduction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRequest {
    pub namespace: String,
    pub signature: String,
    pub observations: Vec<ObservationView>,
    pub distinct_operations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigateReport {
    pub filing: FilingDecision,
    pub investigation_id: String,
    pub finding_id: String,
    pub hypothesis_ids: Vec<String>,
    /// False when an earlier dispatch in the same bucket already ran the model.
    pub analyzed: bool,
}

#[derive(Debug)]
pub enum AnalysisError {
    BudgetExhausted,
    Malformed(String),
    Unavailable(String),
}

/// Produces one structured analysis of an observation cluster.
pub trait FeedbackAnalyzer {
    async fn analyze(
        &self,
        request: &AnalysisRequest,
    ) -> Result<InvestigationAnalysis, AnalysisError>;
}

/// Split occurrence identifiers. Replayed delivery of one id is one operation.
pub fn parse_occurrence_ids(raw: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|id| !id.is_empty() && seen.insert(id.to_string()))
        .map(str::to_string)
        .collect()
}

pub fn observation_view(object: &Object) -> Option<ObservationView> {
    if object.kind != KIND_OBSERVATION {
        return None;
    }
    let property = |key: &str| object.properties.get(key).cloned().unwrap_or_default();
    let signature = property("problem_signature").trim().to_string();
    if signature.is_empty() {
        return None;
    }
    Some(ObservationView {
        object_id: object.id.clone(),
        created_ms: object.created,
        problem_signature: signature,
        occurrence_ids: parse_occurrence_ids(&property("occurrence_ids")),
        classification: property("classification"),
        disposition: property("disposition"),
    })
}

/// Application failures, cancellation, and expected waits are not Tenkai defects.
pub fn precludes_tenkai_defect(observation: &ObservationView) -> bool {
    if matches!(
        observation.classification.as_str(),
        "cancelled" | "blocked" | "ok" | "reconciled"
    ) {
        return true;
    }
    observation
        .problem_signature
        .rsplit_once(':')
        .is_some_and(|(_, reason)| {
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
    let distinct_operations = in_window
        .iter()
        .flat_map(|observation| observation.occurrence_ids.iter())
        .filter(|occurrence| seen.insert(occurrence.as_str()))
        .cloned()
        .collect();
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
    ) || cluster.observations.iter().all(precludes_tenkai_defect)
    {
        return FilingDecision::Internal;
    }
    if cluster.has_measured_reproduction {
        return FilingDecision::Qualifying;
    }
    if analysis.attribution == Attribution::Tenkai
        && cluster.distinct_operations.len() >= MIN_RECURRING_OPERATIONS
    {
        FilingDecision::Qualifying
    } else {
        FilingDecision::Internal
    }
}

/// A qualifying finding the investigation runtime recorded. Writer-submitted
/// findings carry no recorder stamp and never publish.
pub fn publication_permitted(finding: &Object) -> bool {
    let property = |key: &str| finding.properties.get(key).map(String::as_str);
    finding.kind == KIND_FINDING
        && property("classification") == Some(CLASSIFICATION_QUALIFYING)
        && property(PROPERTY_RECORDED_BY) == Some(INVESTIGATION_RUNTIME)
}

pub fn analysis_system_prompt() -> &'static str {
    "You investigate Tenkai application observations. Reply with one JSON object only, no tools, no code. Keys: observed_facts (string array), hypotheses (string array), impact (string), attribution (tenkai|application|expected_wait|cancellation|inconclusive|malformed), proposed_reproduction (string), missing_evidence (string array), independently_verified_reproduction (boolean, true only for a measured reproduction you did not invent)."
}

/// The cluster, bounded: counts plus the newest [`PROMPT_OBSERVATION_CAP`]
/// observations, so the prompt does not grow with the cluster.
pub fn analysis_prompt(request: &AnalysisRequest) -> String {
    let listed = request.observations.len().min(PROMPT_OBSERVATION_CAP);
    let mut body = format!(
        "Signature: {}\nObservations in window: {}\nDistinct operations: {}\nNewest {listed}:\n",
        request.signature,
        request.observations.len(),
        request.distinct_operations,
    );
    for observation in request.observations.iter().rev().take(listed) {
        body.push_str(&format!(
            "- id={} occurrences={} classification={} disposition={}\n",
            observation.object_id,
            observation.occurrence_ids.join(","),
            observation.classification,
            observation.disposition
        ));
    }
    body
}

/// Planner input for one analysis. The prompt goes in `spec` only: the
/// planner appends `spec` to non-empty `messages`, which would send it twice.
pub fn analysis_input(request: &AnalysisRequest, principal: &str) -> ExecutionInput {
    let spec = analysis_prompt(request);
    ExecutionInput {
        request_id: format!("feedback-inv-{}", bucket_key(request, 0)),
        namespace: request.namespace.clone(),
        estimated_tokens: estimated_tokens(&spec),
        spec,
        user_id: principal.into(),
        max_tokens: 1_024,
        messages: Vec::new(),
        system: analysis_system_prompt().into(),
        tools: Vec::new(),
        ..Default::default()
    }
}

/// Prompt plus reply budget, at roughly four bytes per token.
fn estimated_tokens(spec: &str) -> i32 {
    let prompt = (spec.len() + analysis_system_prompt().len()).div_ceil(4);
    i32::try_from(prompt)
        .unwrap_or(i32::MAX)
        .saturating_add(1_024)
}

pub fn parse_model_analysis_json(raw: &str) -> Result<InvestigationAnalysis, AnalysisError> {
    let start = raw.find('{');
    let end = raw.rfind('}');
    let json = match (start, end) {
        (Some(start), Some(end)) if start <= end => &raw[start..=end],
        _ => {
            return Err(AnalysisError::Malformed(
                "model result is not a JSON object".into(),
            ));
        }
    };
    serde_json::from_str(json).map_err(|error| AnalysisError::Malformed(error.to_string()))
}

/// Analysis through the governed planner: `PlanExecution`, then
/// `ExecutePlanStream`. Budget refusal is reported, not retried.
pub struct PlanAnalyzer<'a> {
    pub chisei: &'a ChiseiServiceImpl,
    pub principal: &'a str,
}

impl FeedbackAnalyzer for PlanAnalyzer<'_> {
    async fn analyze(
        &self,
        request: &AnalysisRequest,
    ) -> Result<InvestigationAnalysis, AnalysisError> {
        let planned = self
            .chisei
            .plan_execution(
                with_principal(
                    PlanExecutionRequest {
                        input: Some(analysis_input(request, self.principal)),
                        gunshi_allocation: None,
                        routing_profile_id: String::new(),
                    },
                    self.principal,
                )
                .map_err(AnalysisError::Unavailable)?,
            )
            .await
            .map_err(status_to_analysis)?
            .into_inner()
            .plan
            .ok_or_else(|| AnalysisError::Unavailable("plan omitted".into()))?;
        if !planned.executable {
            return Err(AnalysisError::Unavailable("plan is not executable".into()));
        }
        let mut stream = self
            .chisei
            .execute_plan_stream(
                with_principal(
                    ExecutePlanRequest {
                        plan: Some(planned),
                    },
                    self.principal,
                )
                .map_err(AnalysisError::Unavailable)?,
            )
            .await
            .map_err(status_to_analysis)?
            .into_inner();
        let mut content = String::new();
        while let Some(event) = stream.next().await {
            let event = event.map_err(status_to_analysis)?;
            match event.response {
                Some(response) if event.done => content = response.content,
                _ => content.push_str(&event.content_delta),
            }
        }
        parse_model_analysis_json(&content)
    }
}

fn status_to_analysis(status: Status) -> AnalysisError {
    if status.code() == Code::ResourceExhausted {
        AnalysisError::BudgetExhausted
    } else {
        AnalysisError::Unavailable(status.message().into())
    }
}

/// One investigation runtime for one namespace and its dispatch binding.
pub struct Investigator {
    pub namespace: String,
    /// The `feedback.investigation.dispatch` binding on observation creates.
    pub binding_id: String,
    /// Unique per process. Every runtime claims as [`INVESTIGATION_RUNTIME`],
    /// and the plane replays a live claim to a matching request id, so the
    /// request id carries this to keep two processes fenced apart.
    pub instance_id: String,
}

impl Investigator {
    /// Advance the dispatch binding. Safe on every runtime at once: the plane
    /// fences subscription positions. The binding is a change subscription:
    /// the first run arms it, and observations created before that never
    /// dispatch.
    pub async fn run_binding(&self, sekai: &SekaiServiceImpl) -> Result<(), String> {
        sekai
            .run_action_binding(with_principal(
                RunActionBindingRequest {
                    namespace: self.namespace.clone(),
                    binding_id: self.binding_id.clone(),
                    limit: BINDING_RUN_LIMIT,
                },
                INVESTIGATION_RUNTIME,
            )?)
            .await
            .map(|_| ())
            .map_err(|status| status.message().to_string())
    }

    /// Claim and investigate one dispatch. `Ok(None)` when nothing is claimable.
    /// A transient failure (budget, model, or plane unavailable) leaves the
    /// claim unacked: it expires and the plane offers the dispatch again,
    /// dead-lettering it after its lease-expiry limit.
    pub async fn run_once<A: FeedbackAnalyzer>(
        &self,
        sekai: &SekaiServiceImpl,
        analyzer: &A,
        now_ms: i64,
    ) -> Result<Option<InvestigateReport>, String> {
        let Some((effect, observation_id)) = self.claim(sekai).await? else {
            return Ok(None);
        };
        match self
            .investigate(sekai, analyzer, &observation_id, now_ms)
            .await
        {
            Ok(report) => {
                self.ack(sekai, &effect, ACK_COMPLETED, "").await?;
                Ok(Some(report))
            }
            Err(Investigation::BudgetExhausted) => {
                Err("model budget exhausted; the dispatch retries after its claim expires".into())
            }
            Err(Investigation::Failed(error)) => Err(error),
            Err(Investigation::Invalid(error)) => {
                // The claim expires and another runtime retries if this ack is lost.
                let _ = self
                    .ack(sekai, &effect, ACK_FAILED, "invalid_dispatch")
                    .await;
                Err(error)
            }
        }
    }

    /// Distinct per process: the plane hands a live claim back to a request
    /// with the same runtime and request id.
    pub fn claim_request_id(&self, effect_id: &str) -> String {
        format!("feedback-claim-{}-{effect_id}", self.instance_id)
    }

    /// Take one fenced dispatch claim with its observation id. `run_once`
    /// calls this; runners that split claim from work may call it directly.
    pub async fn claim(
        &self,
        sekai: &SekaiServiceImpl,
    ) -> Result<Option<(ActionEffect, String)>, String> {
        let claimable = sekai
            .list_claimable_action_work(with_principal(
                ListClaimableActionWorkRequest {
                    namespace: self.namespace.clone(),
                    runtime_id: INVESTIGATION_RUNTIME.into(),
                    limit: CLAIMABLE_PAGE,
                },
                INVESTIGATION_RUNTIME,
            )?)
            .await
            .map_err(|status| status.message().to_string())?
            .into_inner()
            .effects;
        for effect in claimable {
            let Some(instance) = sekai
                .get_action_instance(with_principal(
                    GetActionInstanceRequest {
                        instance_id: effect.instance_id.clone(),
                        ..Default::default()
                    },
                    INVESTIGATION_RUNTIME,
                )?)
                .await
                .map_err(|status| status.message().to_string())?
                .into_inner()
                .instance
            else {
                continue;
            };
            // Work routed to this runtime that it cannot do is claimed and
            // failed, so it never stays claimable ahead of real dispatches.
            let observation_id = (instance.type_id == ACTION_DISPATCH)
                .then(|| dispatch_observation(&instance.parameters_json))
                .flatten();
            // Another runtime may win the race; that dispatch is theirs.
            let Ok(claimed) = sekai
                .claim_action_work(with_principal(
                    ClaimActionWorkRequest {
                        effect_id: effect.effect_id.clone(),
                        runtime_id: INVESTIGATION_RUNTIME.into(),
                        request_id: self.claim_request_id(&effect.effect_id),
                        ttl_ms: CLAIM_TTL_MS,
                    },
                    INVESTIGATION_RUNTIME,
                )?)
                .await
            else {
                continue;
            };
            let Some(effect) = claimed.into_inner().effect else {
                continue;
            };
            match observation_id {
                Some(observation_id) => return Ok(Some((effect, observation_id))),
                None => {
                    self.ack(sekai, &effect, ACK_FAILED, "invalid_dispatch")
                        .await?
                }
            }
        }
        Ok(None)
    }

    async fn ack(
        &self,
        sekai: &SekaiServiceImpl,
        effect: &ActionEffect,
        outcome: &str,
        reason: &str,
    ) -> Result<(), String> {
        sekai
            .ack_action_work(with_principal(
                AckActionWorkRequest {
                    effect_id: effect.effect_id.clone(),
                    runtime_id: INVESTIGATION_RUNTIME.into(),
                    claim_generation: effect.claim_generation,
                    fencing_token: effect.claim_fencing_token.clone(),
                    outcome: outcome.into(),
                    reason: reason.into(),
                    request_id: format!("feedback-claim-{}", effect.effect_id),
                    ..Default::default()
                },
                INVESTIGATION_RUNTIME,
            )?)
            .await
            .map(|_| ())
            .map_err(|status| status.message().to_string())
    }

    async fn investigate<A: FeedbackAnalyzer>(
        &self,
        sekai: &SekaiServiceImpl,
        analyzer: &A,
        observation_id: &str,
        now_ms: i64,
    ) -> Result<InvestigateReport, Investigation> {
        let cluster = self.gather_cluster(sekai, observation_id, now_ms).await?;
        let request = AnalysisRequest {
            namespace: cluster.namespace.clone(),
            signature: cluster.signature.clone(),
            observations: cluster.observations.clone(),
            distinct_operations: cluster.distinct_operations.len(),
        };
        let key = bucket_key(&request, now_ms);
        let investigation_id = format!("fb-inv-{key}");
        let (anchor, analyzed) = match self.get(sekai, &investigation_id).await? {
            Some(stored) => (BucketAnchor::from_stored(&stored, &cluster), false),
            None => {
                let analysis = match analyzer.analyze(&request).await {
                    Ok(analysis) => analysis,
                    Err(AnalysisError::BudgetExhausted) => {
                        return Err(Investigation::BudgetExhausted);
                    }
                    Err(AnalysisError::Malformed(_)) => {
                        InvestigationAnalysis::empty(Attribution::Malformed)
                    }
                    // Never anchor an outage: it would hold the bucket all window.
                    Err(AnalysisError::Unavailable(error)) => {
                        return Err(Investigation::Failed(error));
                    }
                };
                let anchor = BucketAnchor {
                    analysis,
                    observation_id: cluster.trigger_id.clone(),
                };
                match self
                    .write_investigation(sekai, &cluster, &anchor, &investigation_id, &key)
                    .await
                {
                    Ok(()) => (anchor, true),
                    // Another runtime wrote this bucket first; its record wins.
                    Err(error) => match self.get(sekai, &investigation_id).await? {
                        Some(stored) => (BucketAnchor::from_stored(&stored, &cluster), false),
                        None => return Err(error),
                    },
                }
            }
        };
        let filing = decide_filing(&cluster, &anchor.analysis);
        self.write_records(sekai, &cluster, &anchor, filing, &key)
            .await
            .map(|(finding_id, hypothesis_ids)| InvestigateReport {
                filing,
                investigation_id,
                finding_id,
                hypothesis_ids,
                analyzed,
            })
    }

    async fn gather_cluster(
        &self,
        sekai: &SekaiServiceImpl,
        observation_id: &str,
        now_ms: i64,
    ) -> Result<ObservationCluster, Investigation> {
        let trigger = self
            .get(sekai, observation_id)
            .await?
            .filter(|object| object.namespace == self.namespace)
            .as_ref()
            .and_then(observation_view)
            .ok_or_else(|| {
                Investigation::Invalid(format!(
                    "{observation_id} is not a visible observation in {}",
                    self.namespace
                ))
            })?;
        let views = self
            .list(
                sekai,
                KIND_OBSERVATION,
                eq_property("problem_signature", &trigger.problem_signature),
            )
            .await?
            .iter()
            .filter_map(observation_view)
            .collect();
        let measured = self
            .has_measured_reproduction(sekai, &trigger.problem_signature)
            .await?;
        Ok(cluster_from_observations(
            &self.namespace,
            observation_id,
            &trigger.problem_signature,
            now_ms,
            views,
            measured,
        ))
    }

    async fn has_measured_reproduction(
        &self,
        sekai: &SekaiServiceImpl,
        signature: &str,
    ) -> Result<bool, Investigation> {
        let measured = self
            .list(
                sekai,
                KIND_INVESTIGATION_RESULT,
                eq_property("measured", "true"),
            )
            .await?;
        for result in measured {
            if result.properties.get("outcome").map(String::as_str)
                == Some(OUTCOME_QUALITY_EVALUATION)
            {
                continue;
            }
            let Some(observation_id) = result.properties.get("observation_id") else {
                continue;
            };
            if let Some(observation) = self.get(sekai, observation_id).await?
                && observation
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

    /// The first analysis of a bucket. Its outcome holds the whole analysis,
    /// so later dispatches rebuild the same records from it.
    async fn write_investigation(
        &self,
        sekai: &SekaiServiceImpl,
        cluster: &ObservationCluster,
        anchor: &BucketAnchor,
        investigation_id: &str,
        key: &str,
    ) -> Result<(), Investigation> {
        let outcome = serde_json::to_string(&anchor.analysis)
            .map_err(|error| Investigation::Failed(error.to_string()))?;
        self.submit(
            sekai,
            ACTION_INVESTIGATION,
            serde_json::json!({
                "object_id": investigation_id,
                "name": cluster.signature,
                "observation_id": anchor.observation_id,
                "outcome": outcome,
                // Model-proposed independently_verified_reproduction is not measured.
                "measured": false,
            }),
            &format!("feedback:inv:{key}"),
        )
        .await
    }

    /// Hypotheses and the finding, derived only from the bucket anchor so every
    /// dispatch in the bucket replays identical submissions. One finding per
    /// bucket and classification: a cluster that crosses the recurrence
    /// threshold gets its qualifying finding.
    async fn write_records(
        &self,
        sekai: &SekaiServiceImpl,
        cluster: &ObservationCluster,
        anchor: &BucketAnchor,
        filing: FilingDecision,
        key: &str,
    ) -> Result<(String, Vec<String>), Investigation> {
        let mut hypothesis_ids = Vec::new();
        for (index, statement) in anchor.analysis.hypotheses.iter().enumerate() {
            let hypothesis_id = format!("fb-hyp-{key}-{index}");
            self.submit(
                sekai,
                ACTION_HYPOTHESIS,
                serde_json::json!({
                    "object_id": hypothesis_id,
                    "name": cluster.signature,
                    "observation_id": anchor.observation_id,
                    "statement": statement,
                }),
                &format!("feedback:hyp:{key}:{index}"),
            )
            .await?;
            hypothesis_ids.push(hypothesis_id);
        }
        let finding_id = format!("fb-find-{key}-{}", filing.classification());
        self.submit(
            sekai,
            ACTION_FINDING,
            serde_json::json!({
                "object_id": finding_id,
                "name": cluster.signature,
                "observation_id": anchor.observation_id,
                "statement": format!(
                    "filing={} attribution={:?} impact={}",
                    filing.classification(),
                    anchor.analysis.attribution,
                    anchor.analysis.impact
                ),
                "classification": filing.classification(),
            }),
            &format!("feedback:find:{key}:{}", filing.classification()),
        )
        .await?;
        Ok((finding_id, hypothesis_ids))
    }

    async fn submit(
        &self,
        sekai: &SekaiServiceImpl,
        type_id: &str,
        parameters: serde_json::Value,
        idempotency_key: &str,
    ) -> Result<(), Investigation> {
        sekai
            .submit_action_instance(
                with_principal(
                    SubmitActionInstanceRequest {
                        namespace: self.namespace.clone(),
                        type_id: type_id.into(),
                        version: PACKAGE_VERSION.into(),
                        parameters_json: parameters.to_string(),
                        idempotency_key: idempotency_key.into(),
                        ..Default::default()
                    },
                    INVESTIGATION_RUNTIME,
                )
                .map_err(Investigation::Failed)?,
            )
            .await
            .map(|_| ())
            .map_err(|status| match status.code() {
                Code::ResourceExhausted => Investigation::BudgetExhausted,
                _ => Investigation::Failed(status.message().into()),
            })
    }

    async fn get(
        &self,
        sekai: &SekaiServiceImpl,
        id: &str,
    ) -> Result<Option<Object>, Investigation> {
        match sekai
            .get_object(
                with_principal(GetObjectRequest { id: id.into() }, INVESTIGATION_RUNTIME)
                    .map_err(Investigation::Failed)?,
            )
            .await
        {
            Ok(response) => Ok(response.into_inner().object),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(Investigation::Failed(status.message().into())),
        }
    }

    /// Every matching object in the namespace, paged past the list cap.
    async fn list(
        &self,
        sekai: &SekaiServiceImpl,
        kind: &str,
        filter: PropertyFilter,
    ) -> Result<Vec<Object>, Investigation> {
        let mut objects = Vec::new();
        let mut page_token = String::new();
        loop {
            let page = sekai
                .list_objects(
                    with_principal(
                        ListObjectsRequest {
                            filter: Some(ListFilter {
                                kind: kind.into(),
                                namespace: self.namespace.clone(),
                                property_filters: vec![filter.clone()],
                                limit: LIST_PAGE,
                                ..Default::default()
                            }),
                            page_token,
                        },
                        INVESTIGATION_RUNTIME,
                    )
                    .map_err(Investigation::Failed)?,
                )
                .await
                .map_err(|status| Investigation::Failed(status.message().into()))?
                .into_inner();
            objects.extend(page.objects);
            if page.next_page_token.is_empty() {
                return Ok(objects);
            }
            page_token = page.next_page_token;
        }
    }
}

enum Investigation {
    /// Transient: retried when the claim expires.
    BudgetExhausted,
    /// Transient: retried when the claim expires.
    Failed(String),
    /// The dispatch can never succeed; acked as failed.
    Invalid(String),
}

/// (namespace, signature, window bucket), so one recurring problem costs one
/// model call per window however many observations arrive.
fn bucket_key(request: &AnalysisRequest, now_ms: i64) -> String {
    let material = format!(
        "{}\0{}\0{}",
        request.namespace,
        request.signature,
        now_ms.div_euclid(RECURRENCE_WINDOW_MS)
    );
    format!("{:x}", Sha256::digest(material.as_bytes()))[..16].to_string()
}

/// The analysis an earlier dispatch in this bucket stored. Unreadable
/// outcomes stay internal rather than re-running the model.
/// What every record in one bucket derives from: the first analysis and the
/// observation that triggered it.
struct BucketAnchor {
    analysis: InvestigationAnalysis,
    observation_id: String,
}

impl BucketAnchor {
    fn from_stored(investigation: &Object, cluster: &ObservationCluster) -> Self {
        let property = |key: &str| investigation.properties.get(key);
        Self {
            analysis: property("outcome")
                .and_then(|outcome| serde_json::from_str(outcome).ok())
                .unwrap_or_else(|| InvestigationAnalysis::empty(Attribution::Inconclusive)),
            observation_id: property("observation_id")
                .cloned()
                .unwrap_or_else(|| cluster.trigger_id.clone()),
        }
    }
}

fn dispatch_observation(parameters_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()?
        .get("observation_id")?
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn eq_property(key: &str, value: &str) -> PropertyFilter {
    PropertyFilter {
        key: key.into(),
        op: "eq".into(),
        value: value.into(),
    }
}

fn with_principal<T>(payload: T, principal: &str) -> Result<Request<T>, String> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).map_err(|error| error.to_string())?,
    );
    Ok(request)
}
