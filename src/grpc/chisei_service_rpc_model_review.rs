use super::*;
use crate::chisei::model_review::{
    self, FamilyEnablementRecord, MODEL_REVIEW_CONTRACT, ModelReviewRecord, ModelReviewStatus,
};

fn require_model_review_admin(
    service: &ChiseiServiceImpl,
    actor: &str,
    context: Option<&crate::enterprise::AuthenticatedContext>,
    namespace: &str,
) -> Result<(), Status> {
    if namespace != namespace.trim() {
        return Err(Status::invalid_argument("namespace must be trimmed"));
    }
    if namespace.is_empty() {
        if context.is_some() {
            return Err(Status::permission_denied(
                "instance model review requires credential administration",
            ));
        }
        if matches!(actor, "root" | "local") {
            return Ok(());
        }
        return Err(Status::permission_denied("credential admin required"));
    }
    require_namespace_admin_access(service.sekai_facts.reader(), actor, context, namespace)
}

fn parse_identity(
    identity: Option<crate::grpc::pb::chisei::ModelReviewIdentity>,
) -> Result<(String, String, String), Status> {
    let identity = identity.ok_or_else(|| Status::invalid_argument("identity is required"))?;
    crate::chisei::model_review::validate_identifier("provider", &identity.provider)
        .map_err(Status::invalid_argument)?;
    crate::chisei::model_review::validate_identifier("model", &identity.model)
        .map_err(Status::invalid_argument)?;
    crate::chisei::model_review::validate_digest(&identity.artifact_digest)
        .map_err(Status::invalid_argument)?;
    Ok((identity.provider, identity.model, identity.artifact_digest))
}

fn parse_status(status: &str) -> Result<ModelReviewStatus, Status> {
    ModelReviewStatus::parse(status).map_err(Status::invalid_argument)
}

fn model_review_status(error: String) -> Status {
    if error.contains("required")
        || error.contains("trimmed")
        || error.contains("unknown")
        || error.contains("exceeds")
        || error.contains("region_label")
        || error.contains("artifact_digest")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal("model review unavailable")
    }
}

fn to_proto_model(record: ModelReviewRecord) -> crate::grpc::pb::chisei::ModelReviewRecord {
    crate::grpc::pb::chisei::ModelReviewRecord {
        namespace: record.namespace,
        identity: Some(crate::grpc::pb::chisei::ModelReviewIdentity {
            provider: record.identity.provider,
            model: record.identity.model,
            artifact_digest: record.identity.artifact_digest,
        }),
        status: record.status.as_str().into(),
        actor: record.actor,
        reason: record.reason,
        updated_at_ms: record.updated_at_ms,
    }
}

fn to_proto_family(
    record: FamilyEnablementRecord,
) -> crate::grpc::pb::chisei::FamilyEnablementRecord {
    crate::grpc::pb::chisei::FamilyEnablementRecord {
        namespace: record.namespace,
        region_label: record.region_label,
        family_id: record.family_id,
        status: record.status.as_str().into(),
        actor: record.actor,
        reason: record.reason,
        updated_at_ms: record.updated_at_ms,
    }
}

pub(super) async fn set_model_review(
    service: &ChiseiServiceImpl,
    req: Request<SetModelReviewRequest>,
) -> Result<Response<SetModelReviewResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_model_review_admin(service, &actor, context.as_ref(), &request.namespace)?;
    let (provider, model, artifact_digest) = parse_identity(request.identity)?;
    let record = model_review::set_model_review(
        &service.db,
        ModelReviewRecord {
            namespace: request.namespace,
            identity: crate::chisei::model_review::ModelReviewIdentity::new(
                provider,
                model,
                artifact_digest,
            ),
            status: parse_status(&request.status)?,
            actor,
            reason: request.reason,
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
    .map_err(model_review_status)?;
    Ok(Response::new(SetModelReviewResponse {
        record: Some(to_proto_model(record)),
    }))
}

pub(super) async fn revoke_model_review(
    service: &ChiseiServiceImpl,
    req: Request<RevokeModelReviewRequest>,
) -> Result<Response<RevokeModelReviewResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_model_review_admin(service, &actor, context.as_ref(), &request.namespace)?;
    let (provider, model, artifact_digest) = parse_identity(request.identity)?;
    let record = model_review::revoke_model_review(
        &service.db,
        ModelReviewRecord {
            namespace: request.namespace,
            identity: crate::chisei::model_review::ModelReviewIdentity::new(
                provider,
                model,
                artifact_digest,
            ),
            status: ModelReviewStatus::Revoked,
            actor,
            reason: request.reason,
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
    .map_err(model_review_status)?;
    Ok(Response::new(RevokeModelReviewResponse {
        record: Some(to_proto_model(record)),
    }))
}

pub(super) async fn list_model_reviews(
    service: &ChiseiServiceImpl,
    req: Request<ListModelReviewsRequest>,
) -> Result<Response<ListModelReviewsResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_model_review_admin(service, &actor, context.as_ref(), &request.namespace)?;
    let records = model_review::list_model_reviews(&service.db, &request.namespace)
        .map_err(model_review_status)?;
    Ok(Response::new(ListModelReviewsResponse {
        records: records.into_iter().map(to_proto_model).collect(),
        contract_version: MODEL_REVIEW_CONTRACT.into(),
    }))
}

pub(super) async fn set_model_family_enablement(
    service: &ChiseiServiceImpl,
    req: Request<SetModelFamilyEnablementRequest>,
) -> Result<Response<SetModelFamilyEnablementResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_model_review_admin(service, &actor, context.as_ref(), &request.namespace)?;
    let record = model_review::set_family_enablement(
        &service.db,
        FamilyEnablementRecord {
            namespace: request.namespace,
            region_label: request.region_label,
            family_id: request.family_id,
            status: parse_status(&request.status)?,
            actor,
            reason: request.reason,
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
    .map_err(model_review_status)?;
    Ok(Response::new(SetModelFamilyEnablementResponse {
        record: Some(to_proto_family(record)),
    }))
}

pub(super) async fn revoke_model_family_enablement(
    service: &ChiseiServiceImpl,
    req: Request<RevokeModelFamilyEnablementRequest>,
) -> Result<Response<RevokeModelFamilyEnablementResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_model_review_admin(service, &actor, context.as_ref(), &request.namespace)?;
    let record = model_review::revoke_family_enablement(
        &service.db,
        FamilyEnablementRecord {
            namespace: request.namespace,
            region_label: request.region_label,
            family_id: request.family_id,
            status: ModelReviewStatus::Revoked,
            actor,
            reason: request.reason,
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
    .map_err(model_review_status)?;
    Ok(Response::new(RevokeModelFamilyEnablementResponse {
        record: Some(to_proto_family(record)),
    }))
}

pub(super) async fn list_model_family_enablement(
    service: &ChiseiServiceImpl,
    req: Request<ListModelFamilyEnablementRequest>,
) -> Result<Response<ListModelFamilyEnablementResponse>, Status> {
    let actor = required_authenticated_actor(&req)?;
    let context = enterprise_authenticated_context(&req)?.cloned();
    let request = req.into_inner();
    require_model_review_admin(service, &actor, context.as_ref(), &request.namespace)?;
    let records = model_review::list_family_enablement(&service.db, &request.namespace)
        .map_err(model_review_status)?;
    Ok(Response::new(ListModelFamilyEnablementResponse {
        records: records.into_iter().map(to_proto_family).collect(),
        contract_version: MODEL_REVIEW_CONTRACT.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn malformed_region_is_invalid_argument() {
        let status = model_review_status(model_review::validate_region("eu/central").unwrap_err());
        assert_eq!(status.code(), Code::InvalidArgument);
    }
}
