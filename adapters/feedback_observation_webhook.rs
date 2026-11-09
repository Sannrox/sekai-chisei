//! Reference receiver for signed Tenkai `feedback.observation` webhook
//! deliveries (#2176).
//!
//! Tenkai posts one captured `tenkai.feedback_observation.v1` record per
//! delivery, HMAC-SHA256 signed over the raw body, and retries under a stable
//! `X-Tenkai-Idempotency-Key`. [`Receiver::receive`] verifies the signature
//! before parsing, validates the body against the vendored schema, then
//! records it with two existing RPCs: `SubmitEvidence` (through the adapter
//! SDK outbox) and `SubmitActionInstance` for `feedback.observation.record`,
//! both keyed on the delivery's idempotency key.
//!
//! The outbox entry completes only once the observation Action is admitted. A
//! crash between the two calls leaves it pending, and
//! [`Receiver::replay_pending`] finishes it into the same observation. A
//! completed entry keeps its envelope, so a later redelivery resubmits the
//! same bytes and the plane replays the same evidence and Action. An entry
//! the plane never admitted and that aged past the producer's replay window
//! is collected again with a new timestamp.
//!
//! The webhook secret and the producer principal belong to the receiver; they
//! never enter the plane, the evidence, or object properties. Hosting the
//! receiver behind HTTP is a deployment decision outside this module.

use std::collections::HashMap;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    EvidenceEnvelope, SubmitActionInstanceRequest, SubmitActionInstanceResponse,
    SubmitEvidenceRequest, SubmitEvidenceResponse,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::feedback_package::{
    ACTION_OBSERVATION, EVIDENCE_SCHEMA_VERSION, EVIDENCE_TYPE, KIND_OBSERVATION, PACKAGE_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tonic::metadata::MetadataValue;
use tonic::{Request, Response, Status};

use crate::sdk::{self, AdapterConfig, ConformanceProfile, EvidenceDraft};

/// The published Tenkai observation schema, vendored byte for byte from
/// `Sannrox/tenkai` `api/tenkai-feedback-observation-v1.schema.json` at
/// 24ffc7079484b86b4a7fc8a8988651568c9b7fd9.
pub const TENKAI_SCHEMA_JSON: &str =
    include_str!("fixtures/tenkai-feedback-observation-v1.schema.json");
/// SHA-256 of [`TENKAI_SCHEMA_JSON`]; a re-vendored schema must update it.
pub const TENKAI_SCHEMA_SHA256: &str =
    "4117e15c32563b82079734451cf69c9a326288fbd3db1fb49c37e13489bd5470";
pub const TENKAI_SCHEMA: &str = "tenkai.feedback_observation.v1";
pub const TENKAI_SCHEMA_VERSION: &str = "1.0.0";

/// `X-Tenkai-Event` value this receiver accepts.
pub const EVENT: &str = "feedback.observation";
pub const SOURCE_TYPE: &str = "tenkai_feedback_webhook";
pub const CONFORMANCE_PROFILE: ConformanceProfile = ConformanceProfile {
    source_type: SOURCE_TYPE,
    evidence_type: EVIDENCE_TYPE,
    signal: "other",
    schema_id: EVIDENCE_TYPE,
    schema_version: EVIDENCE_SCHEMA_VERSION,
    delivery: "webhook",
    requires_expiry: false,
};

/// Schema `maxLength` for every bounded string field.
const MAX_FIELD_CHARS: usize = 256;

/// One webhook delivery as the HTTP host received it.
#[derive(Debug, Clone, Default)]
pub struct Delivery {
    pub body: Vec<u8>,
    pub signature: Option<String>,
    pub event: Option<String>,
    pub idempotency_key: Option<String>,
}

impl Delivery {
    /// Picks the Tenkai headers out of `headers`, matching names
    /// case-insensitively as HTTP requires.
    pub fn from_headers<'a>(
        body: Vec<u8>,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        let mut delivery = Self {
            body,
            ..Self::default()
        };
        for (name, value) in headers {
            let slot = match name.to_ascii_lowercase().as_str() {
                "x-tenkai-signature" => &mut delivery.signature,
                "x-tenkai-event" => &mut delivery.event,
                "x-tenkai-idempotency-key" => &mut delivery.idempotency_key,
                _ => continue,
            };
            *slot = Some(value.to_owned());
        }
        delivery
    }
}

/// Why a delivery was refused before any plane call. Each refusal is final
/// for that delivery: retrying the same bytes is refused the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    MissingSignature,
    BadSignature,
    UnexpectedEvent(String),
    MissingIdempotencyKey,
    /// The body does not match `tenkai.feedback_observation.v1`.
    InvalidObservation(String),
}

impl Refusal {
    /// Stable machine-readable reason for logs and HTTP responses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingSignature => "signature_missing",
            Self::BadSignature => "signature_mismatch",
            Self::UnexpectedEvent(_) => "event_unexpected",
            Self::MissingIdempotencyKey => "idempotency_key_missing",
            Self::InvalidObservation(_) => "observation_invalid",
        }
    }
}

/// A verified delivery could not be recorded yet. The outbox keeps it, and
/// a redelivery or [`Receiver::replay_pending`] retries it.
#[derive(Debug)]
pub enum ReceiveError {
    Refused(Refusal),
    Outbox(String),
    Plane(String),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(Refusal::InvalidObservation(detail)) => {
                write!(formatter, "observation_invalid: {detail}")
            }
            Self::Refused(refusal) => formatter.write_str(refusal.code()),
            Self::Outbox(detail) => write!(formatter, "outbox: {detail}"),
            Self::Plane(detail) => write!(formatter, "plane: {detail}"),
        }
    }
}

impl std::error::Error for ReceiveError {}

impl From<Refusal> for ReceiveError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ApplyStep,
    RuntimeCompletion,
    UnknownReconciliation,
    PlanBlocked,
    PlanFailed,
    OrphanRecovery,
}

impl Operation {
    pub const ALL: [Self; 6] = [
        Self::ApplyStep,
        Self::RuntimeCompletion,
        Self::UnknownReconciliation,
        Self::PlanBlocked,
        Self::PlanFailed,
        Self::OrphanRecovery,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    None,
    ProductFailed,
    ProductFailedRestored,
    TenkaiFailed,
    TenkaiFailedRestored,
    Cancelled,
    Blocked,
    StateUnknown,
    Reconciled,
    Degraded,
    MaintenanceBlocked,
    GateBlocked,
    PlanFailed,
    Abandoned,
}

impl Reason {
    pub const ALL: [Self; 14] = [
        Self::None,
        Self::ProductFailed,
        Self::ProductFailedRestored,
        Self::TenkaiFailed,
        Self::TenkaiFailedRestored,
        Self::Cancelled,
        Self::Blocked,
        Self::StateUnknown,
        Self::Reconciled,
        Self::Degraded,
        Self::MaintenanceBlocked,
        Self::GateBlocked,
        Self::PlanFailed,
        Self::Abandoned,
    ];

    /// Same mapping as Tenkai's direct export, so both paths classify an
    /// outcome alike.
    fn classification(self) -> &'static str {
        match self {
            Self::None => "ok",
            Self::Reconciled => "reconciled",
            Self::Blocked | Self::MaintenanceBlocked | Self::GateBlocked => "blocked",
            Self::Cancelled => "cancelled",
            Self::Degraded => "degraded",
            Self::ProductFailed
            | Self::ProductFailedRestored
            | Self::TenkaiFailed
            | Self::TenkaiFailedRestored
            | Self::StateUnknown
            | Self::PlanFailed
            | Self::Abandoned => "defect",
        }
    }

    fn disposition(self) -> &'static str {
        match self {
            Self::None | Self::Reconciled => "closed",
            _ => "open",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryContext {
    pub failed_target_retry: Option<bool>,
    pub recovery_reason: Option<String>,
    pub runtime_claim_generation: Option<u64>,
    pub takeover: Option<bool>,
}

/// `tenkai.feedback_observation.v1`. Unknown fields are refused, so a field
/// Tenkai adds without a schema version bump fails validation here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: String,
    pub id: String,
    pub operation: Operation,
    pub environment: String,
    pub product: String,
    pub plan_id: String,
    pub step_id: String,
    pub action: String,
    pub release_id: String,
    pub status: String,
    pub reason: Reason,
    pub duration_ms: Option<u64>,
    pub controller_version: String,
    pub lease_generation: u64,
    pub observed_at_ms: i64,
    pub context: Option<RetryContext>,
}

impl Observation {
    /// Schema-required fields, in schema order.
    pub const REQUIRED: [&'static str; 14] = [
        "schema",
        "id",
        "operation",
        "environment",
        "product",
        "plan_id",
        "step_id",
        "action",
        "release_id",
        "status",
        "reason",
        "controller_version",
        "lease_generation",
        "observed_at_ms",
    ];
    pub const OPTIONAL: [&'static str; 2] = ["duration_ms", "context"];

    /// Parses and checks the constraints serde cannot express.
    pub fn parse(body: &[u8]) -> Result<(Self, Value), Refusal> {
        let invalid = |detail: String| Refusal::InvalidObservation(detail);
        let value: Value =
            serde_json::from_slice(body).map_err(|error| invalid(error.to_string()))?;
        // The schema declares no nullable field, but `Option` would read an
        // explicit null as absent.
        if let Some(field) = null_field(&value, "") {
            return Err(invalid(format!("{field} must not be null")));
        }
        let observation: Self =
            serde_json::from_value(value.clone()).map_err(|error| invalid(error.to_string()))?;
        if observation.schema != TENKAI_SCHEMA {
            return Err(invalid(format!("schema must be {TENKAI_SCHEMA}")));
        }
        if observation.id.is_empty() {
            return Err(invalid("id must not be empty".into()));
        }
        // The observation Action needs a scope and a non-negative time.
        if observation.environment.is_empty() {
            return Err(invalid("environment must not be empty".into()));
        }
        if observation.observed_at_ms < 0 {
            return Err(invalid("observed_at_ms must not be negative".into()));
        }
        for (field, text) in observation.bounded_fields() {
            if text.chars().count() > MAX_FIELD_CHARS {
                return Err(invalid(format!(
                    "{field} exceeds {MAX_FIELD_CHARS} characters"
                )));
            }
        }
        Ok((observation, value))
    }

    fn bounded_fields(&self) -> impl Iterator<Item = (&'static str, &str)> {
        let recovery = self
            .context
            .as_ref()
            .and_then(|context| context.recovery_reason.as_deref());
        [
            ("id", Some(self.id.as_str())),
            ("environment", Some(self.environment.as_str())),
            ("product", Some(self.product.as_str())),
            ("plan_id", Some(self.plan_id.as_str())),
            ("step_id", Some(self.step_id.as_str())),
            ("action", Some(self.action.as_str())),
            ("release_id", Some(self.release_id.as_str())),
            ("status", Some(self.status.as_str())),
            ("controller_version", Some(self.controller_version.as_str())),
            ("context.recovery_reason", recovery),
        ]
        .into_iter()
        .filter_map(|(field, text)| text.map(|text| (field, text)))
    }

    /// `feedback.observation.record` parameters, derived as Tenkai's direct
    /// export derives them. Webhook bodies carry no tenant, so the scope is
    /// the environment.
    fn action_parameters(&self, source_evidence: &str) -> Value {
        let reason = snake_case(self.reason);
        let signature_head = if self.product.is_empty() {
            snake_case(self.operation)
        } else {
            self.product.clone()
        };
        let plan = self.plan_id.trim();
        serde_json::json!({
            "object_id": self.id,
            "source_evidence": source_evidence,
            "problem_signature": format!("{signature_head}:{reason}"),
            "occurrence_ids": self.id,
            "classification": self.reason.classification(),
            "disposition": self.reason.disposition(),
            "operation_id": if plan.is_empty() { self.id.as_str() } else { plan },
            "observed_at_ms": self.observed_at_ms,
            "scope": self.environment,
        })
    }
}

/// Path of the first JSON `null` in `value`, if any.
fn null_field(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Null => Some(if path.is_empty() {
            "body".into()
        } else {
            path.into()
        }),
        Value::Object(fields) => fields.iter().find_map(|(name, field)| {
            let path = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            null_field(field, &path)
        }),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(index, item)| null_field(item, &format!("{path}[{index}]"))),
        _ => None,
    }
}

fn snake_case(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The two plane calls the receiver makes. Implemented for the in-process
/// service; a deployment can implement it over its gRPC client.
#[allow(async_fn_in_trait)]
pub trait ObservationPlane {
    async fn submit_evidence(
        &self,
        request: Request<SubmitEvidenceRequest>,
    ) -> Result<Response<SubmitEvidenceResponse>, Status>;
    async fn submit_action_instance(
        &self,
        request: Request<SubmitActionInstanceRequest>,
    ) -> Result<Response<SubmitActionInstanceResponse>, Status>;
}

impl ObservationPlane for SekaiServiceImpl {
    async fn submit_evidence(
        &self,
        request: Request<SubmitEvidenceRequest>,
    ) -> Result<Response<SubmitEvidenceResponse>, Status> {
        SekaiService::submit_evidence(self, request).await
    }

    async fn submit_action_instance(
        &self,
        request: Request<SubmitActionInstanceRequest>,
    ) -> Result<Response<SubmitActionInstanceResponse>, Status> {
        SekaiService::submit_action_instance(self, request).await
    }
}

/// The plane's answer to one evidence submission.
struct Submission {
    admitted: bool,
    id: String,
    rejection_code: String,
}

/// What one delivery recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub evidence_submission_id: String,
    pub action_instance_id: String,
    pub replay: bool,
}

/// Receiver configuration. `secret` verifies deliveries; `producer` is the
/// receiver's own principal, registered as the evidence producer.
pub struct Receiver {
    pub secret: Vec<u8>,
    pub producer: String,
    pub source_instance: String,
    pub namespace: String,
    pub outbox: PathBuf,
}

impl Receiver {
    /// Verifies the signature over the raw body, then the headers, then the
    /// body. Nothing is parsed before the signature matches.
    pub fn verify(&self, delivery: &Delivery) -> Result<(Observation, Value, String), Refusal> {
        let header = delivery
            .signature
            .as_deref()
            .ok_or(Refusal::MissingSignature)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .expect("HMAC-SHA256 accepts keys of any length");
        mac.update(&delivery.body);
        let expected = format!("sha256={:x}", mac.finalize().into_bytes());
        if !bool::from(expected.as_bytes().ct_eq(header.trim().as_bytes())) {
            return Err(Refusal::BadSignature);
        }
        match delivery.event.as_deref() {
            Some(EVENT) => {}
            other => return Err(Refusal::UnexpectedEvent(other.unwrap_or_default().into())),
        }
        let key = delivery
            .idempotency_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .ok_or(Refusal::MissingIdempotencyKey)?
            .to_owned();
        let (observation, content) = Observation::parse(&delivery.body)?;
        Ok((observation, content, key))
    }

    /// Records one delivery: evidence through the outbox, then the
    /// observation Action. A refusal makes no plane call.
    pub async fn receive(
        &self,
        plane: &impl ObservationPlane,
        delivery: &Delivery,
        now_ms: i64,
    ) -> Result<Recorded, ReceiveError> {
        let (observation, content, key) = self.verify(delivery)?;
        let draft = self.draft(&observation, content, &key)?;
        let (envelope, receipt) =
            sdk::prepare_delivery_in(&self.outbox, &self.config(&observation.id), draft, now_ms)
                .map_err(ReceiveError::Outbox)?;
        self.finish(plane, envelope, receipt, now_ms).await
    }

    /// Finishes every delivery left in the outbox, for example after a crash
    /// between evidence and Action. One result per pending entry; a failed
    /// entry stays pending and does not hold back the others.
    pub async fn replay_pending(
        &self,
        plane: &impl ObservationPlane,
        now_ms: i64,
    ) -> Result<Vec<Result<Recorded, ReceiveError>>, ReceiveError> {
        let mut results = Vec::new();
        for pending in sdk::pending_deliveries(&self.outbox).map_err(ReceiveError::Outbox)? {
            results.push(match pending {
                Ok((envelope, receipt)) => self.finish(plane, envelope, receipt, now_ms).await,
                Err(error) => Err(ReceiveError::Outbox(error)),
            });
        }
        Ok(results)
    }

    /// Records one persisted delivery, then keeps its envelope as completed
    /// so a redelivery replays the same bytes.
    async fn finish(
        &self,
        plane: &impl ObservationPlane,
        envelope: EvidenceEnvelope,
        receipt: sdk::OutboxReceipt,
        now_ms: i64,
    ) -> Result<Recorded, ReceiveError> {
        let key = envelope.source_record_id.clone();
        let submitted_key = envelope.idempotency_key.clone();
        let content: Value = serde_json::from_slice(&envelope.content_json)
            .map_err(|error| ReceiveError::Outbox(format!("outbox content: {error}")))?;
        let observation: Observation = serde_json::from_value(content.clone())
            .map_err(|error| ReceiveError::Outbox(format!("outbox content: {error}")))?;
        let mut submission = self.submit_evidence(plane, envelope).await?;
        if !submission.admitted && submission.rejection_code == "replay_window_expired" {
            // Never admitted, and too old to ever be: collect it again now.
            let draft = self.draft(&observation, content, &key)?;
            let restamped = sdk::restamp_delivery(
                &receipt,
                &submitted_key,
                &self.config(&observation.id),
                draft,
                now_ms,
            )
            .map_err(ReceiveError::Outbox)?;
            submission = self.submit_evidence(plane, restamped).await?;
        }
        if !submission.admitted {
            return Err(ReceiveError::Plane(format!(
                "observation evidence was not admitted: {}",
                submission.rejection_code
            )));
        }
        let recorded = self
            .submit_observation(plane, &observation, &key, submission.id)
            .await?;
        receipt.complete().map_err(ReceiveError::Outbox)?;
        Ok(recorded)
    }

    fn config(&self, observation_id: &str) -> AdapterConfig {
        AdapterConfig {
            // Unused: the receiver calls the plane through `ObservationPlane`.
            target: String::new(),
            producer_identity: self.producer.clone(),
            source_instance: self.source_instance.clone(),
            namespace: self.namespace.clone(),
            target_external_id: observation_id.into(),
            target_kind: KIND_OBSERVATION.into(),
            classification: "internal".into(),
        }
    }

    fn draft(
        &self,
        observation: &Observation,
        content: Value,
        key: &str,
    ) -> Result<EvidenceDraft, Refusal> {
        let draft = EvidenceDraft {
            source_type: SOURCE_TYPE.into(),
            // One delivery is one source record; Tenkai reuses the key for
            // every retry of the same observation.
            source_record_id: key.into(),
            source_version: TENKAI_SCHEMA_VERSION.into(),
            source_sequence: observation.observed_at_ms.max(0),
            evidence_type: EVIDENCE_TYPE.into(),
            signal: "other".into(),
            schema_id: EVIDENCE_TYPE.into(),
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            observed_at_ms: observation.observed_at_ms,
            expires_at_ms: None,
            content,
            relationships: Vec::new(),
            confidence_bps: 10_000,
            provenance: HashMap::from([
                ("adapter".into(), "feedback_observation_webhook/v1".into()),
                ("delivery".into(), "webhook".into()),
                ("tenkai_schema".into(), TENKAI_SCHEMA.into()),
                ("tenkai_schema_version".into(), TENKAI_SCHEMA_VERSION.into()),
                ("tenkai_schema_sha256".into(), TENKAI_SCHEMA_SHA256.into()),
                ("observation_id".into(), observation.id.clone()),
                ("environment".into(), observation.environment.clone()),
                ("product".into(), observation.product.clone()),
                ("plan_id".into(), observation.plan_id.clone()),
                ("operation".into(), snake_case(observation.operation)),
                ("reason".into(), snake_case(observation.reason)),
                (
                    "lease_generation".into(),
                    observation.lease_generation.to_string(),
                ),
            ]),
            causality: None,
        };
        CONFORMANCE_PROFILE
            .validate(&draft)
            .map_err(Refusal::InvalidObservation)?;
        Ok(draft)
    }

    async fn submit_evidence(
        &self,
        plane: &impl ObservationPlane,
        envelope: EvidenceEnvelope,
    ) -> Result<Submission, ReceiveError> {
        let result = plane
            .submit_evidence(self.request(SubmitEvidenceRequest {
                envelope: Some(envelope),
            })?)
            .await
            .map_err(|status| plane_error("SubmitEvidence", &status))?
            .into_inner()
            .result
            .ok_or_else(|| ReceiveError::Plane("SubmitEvidence returned no result".into()))?;
        let record = result.submission.unwrap_or_default();
        Ok(Submission {
            admitted: result.admitted && !record.id.is_empty(),
            id: record.id,
            rejection_code: record.rejection_code,
        })
    }

    /// Submits `feedback.observation.record` naming the admitted evidence,
    /// keyed on the delivery so a retry replays the same instance.
    async fn submit_observation(
        &self,
        plane: &impl ObservationPlane,
        observation: &Observation,
        key: &str,
        evidence_submission_id: String,
    ) -> Result<Recorded, ReceiveError> {
        let request = self.request(SubmitActionInstanceRequest {
            namespace: self.namespace.clone(),
            type_id: ACTION_OBSERVATION.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: observation
                .action_parameters(&evidence_submission_id)
                .to_string(),
            idempotency_key: key.into(),
            evidence_submission_ids: vec![evidence_submission_id.clone()],
            request_id: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        })?;
        let response = plane
            .submit_action_instance(request)
            .await
            .map_err(|status| plane_error("SubmitActionInstance", &status))?
            .into_inner();
        let instance = response.instance.ok_or_else(|| {
            ReceiveError::Plane("SubmitActionInstance returned no instance".into())
        })?;
        if instance.status != "admitted" {
            return Err(ReceiveError::Plane(format!(
                "observation Action is {}: {}",
                instance.status, instance.deny_reason
            )));
        }
        Ok(Recorded {
            evidence_submission_id,
            action_instance_id: instance.instance_id,
            replay: response.replay,
        })
    }

    fn request<T>(&self, payload: T) -> Result<Request<T>, ReceiveError> {
        let principal = MetadataValue::try_from(self.producer.as_str())
            .map_err(|_| ReceiveError::Plane("producer principal is not valid metadata".into()))?;
        let mut request = Request::new(payload);
        request.metadata_mut().insert("x-principal", principal);
        Ok(request)
    }
}

fn plane_error(rpc: &str, status: &Status) -> ReceiveError {
    ReceiveError::Plane(format!("{rpc} returned gRPC {:?}", status.code()))
}
