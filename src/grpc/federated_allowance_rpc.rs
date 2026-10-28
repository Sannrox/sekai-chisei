//! Federated aggregate allowance RPCs (#1921, ADR 0134 §1). Each needs
//! administration of the allowance's namespace, like export grants.

use super::*;
use crate::sekai::federated_aggregate::{ALLOWANCE_SCHEMA, AggregateFunction, Allowance};
use crate::sekai::federated_allowance::{self, ALLOWANCE_CHANGED, AllowanceRecord};

fn allowance_status(error: String) -> Status {
    if error == ALLOWANCE_CHANGED {
        Status::aborted(error)
    } else if error.starts_with("reason")
        || error.starts_with("allowance")
        || error.contains("refused")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}

fn from_proto(allowance: FederatedAggregateAllowance) -> Result<Allowance, Status> {
    let functions = allowance
        .functions
        .iter()
        .map(|name| AggregateFunction::parse(name.trim()))
        .collect::<Result<_, _>>()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    let parsed = Allowance {
        schema: ALLOWANCE_SCHEMA.into(),
        namespace: allowance.namespace,
        object_type: allowance.object_type,
        dimensions: allowance.dimensions.into_iter().collect(),
        measures: allowance.measures.into_iter().collect(),
        functions,
        min_group_size: allowance.min_group_size,
        noise_scale: (allowance.noise_scale != 0.0).then_some(allowance.noise_scale),
        requesters: allowance.requesters.into_iter().collect(),
    };
    parsed
        .validate()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    Ok(parsed)
}

fn to_proto(record: AllowanceRecord) -> FederatedAggregateAllowanceRecord {
    let allowance = record.allowance;
    FederatedAggregateAllowanceRecord {
        allowance: Some(FederatedAggregateAllowance {
            namespace: allowance.namespace,
            object_type: allowance.object_type,
            dimensions: allowance.dimensions.into_iter().collect(),
            measures: allowance.measures.into_iter().collect(),
            functions: allowance
                .functions
                .into_iter()
                .map(|function| {
                    match function {
                        AggregateFunction::Count => "count",
                        AggregateFunction::Sum => "sum",
                        AggregateFunction::Avg => "avg",
                    }
                    .to_string()
                })
                .collect(),
            min_group_size: allowance.min_group_size,
            noise_scale: allowance.noise_scale.unwrap_or(0.0),
            requesters: allowance.requesters.into_iter().collect(),
        }),
        allowance_digest: record.allowance_digest,
        published_by: record.published_by,
        published_at_ms: record.published_at_ms,
        reason: record.reason,
        withdrawn_by: record.withdrawn_by,
        withdrawn_at_ms: record.withdrawn_at_ms,
        withdrawal_reason: record.withdrawal_reason,
    }
}

impl SekaiServiceImpl {
    /// Checks the tenant context and namespace administration; returns the actor.
    fn authorize_allowance_admin<T: 'static>(
        &self,
        req: &Request<T>,
        namespace: &str,
    ) -> Result<String, Status> {
        let principals = caller_principals(req);
        let tenant_context = request_tenant_context(self.db.runtime(), req)?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            namespace,
            true,
        )?;
        authorize_source_type_namespace_admin(self, &principals, namespace)
    }

    pub(super) async fn publish_federated_aggregate_allowance_rpc(
        &self,
        req: Request<PublishFederatedAggregateAllowanceRequest>,
    ) -> Result<Response<PublishFederatedAggregateAllowanceResponse>, Status> {
        let namespace = req
            .get_ref()
            .allowance
            .as_ref()
            .map(|allowance| allowance.namespace.clone())
            .ok_or_else(|| Status::invalid_argument("allowance is required"))?;
        let actor = self.authorize_allowance_admin(&req, &namespace)?;
        let inner = req.into_inner();
        let allowance = from_proto(inner.allowance.expect("checked above"))?;
        let record = federated_allowance::publish(
            self.db.runtime(),
            allowance,
            &inner.reason,
            &actor,
            now_millis(),
        )
        .map_err(allowance_status)?;
        Ok(Response::new(PublishFederatedAggregateAllowanceResponse {
            record: Some(to_proto(record)),
        }))
    }

    pub(super) async fn withdraw_federated_aggregate_allowance_rpc(
        &self,
        req: Request<WithdrawFederatedAggregateAllowanceRequest>,
    ) -> Result<Response<WithdrawFederatedAggregateAllowanceResponse>, Status> {
        let namespace = req.get_ref().namespace.clone();
        let actor = self.authorize_allowance_admin(&req, &namespace)?;
        let inner = req.into_inner();
        let record = federated_allowance::withdraw(
            self.db.runtime(),
            &inner.namespace,
            &inner.object_type,
            &inner.reason,
            &actor,
            now_millis(),
        )
        .map_err(allowance_status)?
        .ok_or_else(|| Status::not_found("federated aggregate allowance not found"))?;
        Ok(Response::new(WithdrawFederatedAggregateAllowanceResponse {
            record: Some(to_proto(record)),
        }))
    }

    pub(super) async fn get_federated_aggregate_allowance_rpc(
        &self,
        req: Request<GetFederatedAggregateAllowanceRequest>,
    ) -> Result<Response<GetFederatedAggregateAllowanceResponse>, Status> {
        let namespace = req.get_ref().namespace.clone();
        self.authorize_allowance_admin(&req, &namespace)?;
        let inner = req.into_inner();
        let record =
            federated_allowance::current(self.db.runtime(), &inner.namespace, &inner.object_type)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::not_found("federated aggregate allowance not found"))?;
        Ok(Response::new(GetFederatedAggregateAllowanceResponse {
            record: Some(to_proto(record)),
        }))
    }
}
