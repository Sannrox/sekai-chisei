use super::*;
use crate::chisei::model_release_evidence::{
    self, EvaluationTrustRoots, ModelReleaseFeedback, ModelReleaseIdentity, ModelRuntimeEvidence,
};
use ed25519_dalek::SigningKey;

fn require_release_admin(
    _service: &ChiseiServiceImpl,
    actor: &str,
    context: Option<&crate::enterprise::AuthenticatedContext>,
) -> Result<(), Status> {
    if context.is_some() {
        return Err(Status::permission_denied(
            "model release evidence requires credential administration",
        ));
    }
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    Err(Status::permission_denied("credential admin required"))
}

fn parse_identity(
    identity: Option<crate::grpc::pb::chisei::ModelReleaseIdentity>,
) -> Result<ModelReleaseIdentity, Status> {
    let identity = identity.ok_or_else(|| Status::invalid_argument("identity is required"))?;
    let identity = ModelReleaseIdentity {
        provider: identity.provider,
        model: identity.model,
        profile_version: identity.profile_version,
        artifact_digest: identity.artifact_digest,
        endpoint: identity.endpoint,
    };
    identity.validate().map_err(Status::invalid_argument)?;
    Ok(identity)
}

fn status_from(error: String) -> Status {
    if error.contains("required")
        || error.contains("trimmed")
        || error.contains("must")
        || error.contains("unsupported")
        || error.contains("invalid")
        || error.contains("unavailable")
        || error.contains("trusted")
        || error.contains("signature")
        || error.contains("weak")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal("model release evidence unavailable")
    }
}

fn evaluation_signing_key() -> Result<SigningKey, Status> {
    let raw = std::env::var("SEKAI_MODEL_EVALUATION_SIGNING_KEY")
        .map_err(|_| Status::failed_precondition("evaluation signing key is not configured"))?;
    let bytes = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
                .map_err(|_| Status::invalid_argument("evaluation signing key is not valid hex"))?;
        }
        out
    } else {
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw.trim())
                .map_err(|_| {
                    Status::invalid_argument("evaluation signing key is not valid base64")
                })?;
        decoded.try_into().map_err(|bytes: Vec<u8>| {
            Status::invalid_argument(format!(
                "evaluation signing key must decode to 32 bytes, got {}",
                bytes.len()
            ))
        })?
    };
    Ok(SigningKey::from_bytes(&bytes))
}

pub(super) async fn put_model_release_trust(
    service: &ChiseiServiceImpl,
    req: Request<PutModelReleaseTrustRequest>,
) -> Result<Response<PutModelReleaseTrustResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    require_release_admin(service, &actor, context.as_ref())?;
    let request = req.into_inner();
    let roots: EvaluationTrustRoots = serde_json::from_str(&request.roots_json)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    let stored = model_release_evidence::install_trust_roots(
        &service.db,
        roots,
        chrono::Utc::now().timestamp_millis(),
    )
    .map_err(status_from)?;
    Ok(Response::new(PutModelReleaseTrustResponse {
        roots_json: serde_json::to_string(&stored)
            .map_err(|error| Status::internal(error.to_string()))?,
    }))
}

pub(super) async fn put_model_runtime_evidence(
    service: &ChiseiServiceImpl,
    req: Request<PutModelRuntimeEvidenceRequest>,
) -> Result<Response<PutModelRuntimeEvidenceResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    require_release_admin(service, &actor, context.as_ref())?;
    let request = req.into_inner();
    let evidence = ModelRuntimeEvidence::parse_json(&request.evidence_json)
        .map_err(|failure| Status::invalid_argument(failure.as_str()))?;
    let stored = model_release_evidence::ingest_runtime_evidence(
        &service.db,
        evidence,
        chrono::Utc::now().timestamp_millis(),
    )
    .map_err(status_from)?;
    Ok(Response::new(PutModelRuntimeEvidenceResponse {
        evidence_json: serde_json::to_string(&stored)
            .map_err(|error| Status::internal(error.to_string()))?,
    }))
}

pub(super) async fn get_model_runtime_evidence(
    service: &ChiseiServiceImpl,
    req: Request<GetModelRuntimeEvidenceRequest>,
) -> Result<Response<GetModelRuntimeEvidenceResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    require_release_admin(service, &actor, context.as_ref())?;
    let identity = parse_identity(req.into_inner().identity)?;
    let evidence_json = model_release_evidence::load_runtime_evidence_json(&service.db, &identity)
        .map_err(status_from)?
        .unwrap_or_default();
    Ok(Response::new(GetModelRuntimeEvidenceResponse {
        evidence_json,
    }))
}

pub(super) async fn export_model_evaluation_evidence(
    service: &ChiseiServiceImpl,
    req: Request<ExportModelEvaluationEvidenceRequest>,
) -> Result<Response<ExportModelEvaluationEvidenceResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    require_release_admin(service, &actor, context.as_ref())?;
    let request = req.into_inner();
    let identity = parse_identity(request.identity)?;
    let key = evaluation_signing_key()?;
    let evidence = model_release_evidence::export_evaluation_from_compare(
        &service.db,
        identity,
        &request.eval_suite_id,
        &request.baseline_run_id,
        &request.candidate_run_id,
        &request.eval_run_id,
        &key,
        chrono::Utc::now().timestamp_millis(),
        &actor,
    )
    .map_err(status_from)?;
    Ok(Response::new(ExportModelEvaluationEvidenceResponse {
        evidence_json: serde_json::to_string(&evidence)
            .map_err(|error| Status::internal(error.to_string()))?,
    }))
}

pub(super) async fn put_model_release_feedback(
    service: &ChiseiServiceImpl,
    req: Request<PutModelReleaseFeedbackRequest>,
) -> Result<Response<PutModelReleaseFeedbackResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    require_release_admin(service, &actor, context.as_ref())?;
    let request = req.into_inner();
    let identity = parse_identity(request.identity)?;
    if request.namespace != request.namespace.trim() {
        return Err(Status::invalid_argument("namespace must be trimmed"));
    }
    let record = model_release_evidence::record_model_release_feedback(
        &service.db,
        ModelReleaseFeedback {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: request.namespace,
            identity,
            actor,
            note: request.note,
            recorded_at_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
    .map_err(status_from)?;
    Ok(Response::new(PutModelReleaseFeedbackResponse {
        id: record.id,
    }))
}
