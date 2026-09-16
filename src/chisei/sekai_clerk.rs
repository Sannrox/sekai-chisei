//! gRPC clerk client Chisei uses when it does not own a database (ADR 0082).

use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    ActionInstance, GetGovernedActionTypeRequest, GetObjectRequest,
    GetPersistedOperationReceiptRequest, PersistAdmittedActionRequest,
};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Request, Status};

#[derive(Clone)]
pub struct SekaiClerk {
    endpoint: String,
}

impl SekaiClerk {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    async fn client(&self) -> Result<SekaiServiceClient<Channel>, Status> {
        let channel = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
            .map_err(|error| Status::invalid_argument(error.to_string()))?
            .connect()
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(SekaiServiceClient::new(channel))
    }

    fn authorize<T>(
        mut request: Request<T>,
        authorization: Option<&str>,
    ) -> Result<Request<T>, Status> {
        if let Some(token) = authorization.filter(|token| !token.is_empty()) {
            let value = MetadataValue::try_from(token)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            request.metadata_mut().insert("authorization", value);
        }
        Ok(request)
    }

    pub async fn get_object(
        &self,
        object_id: &str,
        authorization: Option<&str>,
    ) -> Result<crate::grpc::pb::sekai::GetObjectResponse, Status> {
        let mut client = self.client().await?;
        let request = Self::authorize(
            Request::new(GetObjectRequest {
                id: object_id.to_string(),
            }),
            authorization,
        )?;
        Ok(client.get_object(request).await?.into_inner())
    }

    pub async fn get_governed_action_type(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
        authorization: Option<&str>,
    ) -> Result<crate::grpc::pb::sekai::GetGovernedActionTypeResponse, Status> {
        let mut client = self.client().await?;
        let request = Self::authorize(
            Request::new(GetGovernedActionTypeRequest {
                namespace: namespace.to_string(),
                type_id: type_id.to_string(),
                version: version.to_string(),
            }),
            authorization,
        )?;
        Ok(client.get_governed_action_type(request).await?.into_inner())
    }

    pub async fn persist_admitted_action(
        &self,
        instance: ActionInstance,
        ontology_digest: &str,
        authorization: Option<&str>,
    ) -> Result<crate::grpc::pb::sekai::PersistAdmittedActionResponse, Status> {
        let mut client = self.client().await?;
        let request = Self::authorize(
            Request::new(PersistAdmittedActionRequest {
                instance: Some(instance),
                ontology_digest: ontology_digest.to_string(),
                policy_scope: String::new(),
                budget_subject: String::new(),
            }),
            authorization,
        )?;
        Ok(client.persist_admitted_action(request).await?.into_inner())
    }

    pub async fn get_persisted_operation_receipt(
        &self,
        operation_id: &str,
        authorization: Option<&str>,
    ) -> Result<crate::grpc::pb::sekai::GetPersistedOperationReceiptResponse, Status> {
        let mut client = self.client().await?;
        let request = Self::authorize(
            Request::new(GetPersistedOperationReceiptRequest {
                operation_id: operation_id.to_string(),
            }),
            authorization,
        )?;
        Ok(client
            .get_persisted_operation_receipt(request)
            .await?
            .into_inner())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn decide_invoke_instance(
    namespace: &str,
    type_id: &str,
    version: &str,
    parameters_json: &str,
    idempotency_key: &str,
    evidence_submission_ids: &[String],
    request_id: &str,
    actor: &str,
    type_enabled: bool,
    now_ms: i64,
) -> Result<ActionInstance, Status> {
    use crate::sekai::facts::action_instance::{
        STATUS_ADMITTED, STATUS_DENIED, compute_request_digest, validate_parameters_json,
    };

    validate_parameters_json(parameters_json).map_err(Status::invalid_argument)?;
    if namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    if type_id.trim().is_empty() || version.trim().is_empty() {
        return Err(Status::invalid_argument("type_id and version required"));
    }
    if idempotency_key.trim().is_empty() || idempotency_key.chars().any(char::is_whitespace) {
        return Err(Status::invalid_argument("idempotency_key required"));
    }
    let digest = compute_request_digest(
        namespace,
        type_id,
        version,
        parameters_json,
        evidence_submission_ids,
    )
    .map_err(Status::invalid_argument)?;
    let operation_id = if request_id.trim().is_empty() {
        format!("op-gai-{}", uuid::Uuid::new_v4().simple())
    } else {
        request_id.trim().to_string()
    };
    let (status, deny_reason, policy_decision) = if type_enabled {
        (STATUS_ADMITTED, "", "allow")
    } else {
        (STATUS_DENIED, "governed action type is disabled", "deny")
    };
    Ok(ActionInstance {
        instance_id: format!("gai-{}", uuid::Uuid::new_v4().simple()),
        namespace: namespace.to_string(),
        type_id: type_id.to_string(),
        version: version.to_string(),
        principal: actor.to_string(),
        parameters_json: parameters_json.to_string(),
        request_digest: digest,
        idempotency_key: idempotency_key.to_string(),
        operation_id,
        status: status.to_string(),
        deny_reason: deny_reason.to_string(),
        evidence_submission_ids: evidence_submission_ids.to_vec(),
        policy_decision: policy_decision.to_string(),
        budget_decision: "not_configured".to_string(),
        created_at_ms: now_ms,
        decided_at_ms: now_ms,
    })
}
