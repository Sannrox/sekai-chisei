//! Shared computed-property response helpers for query, mutation, and retrieval.
//!
//! These are private implementation used by already-deep modules. They are not a
//! new ordered lifecycle.

use super::*;

impl SekaiServiceImpl {
    pub(super) fn resolve_computed_for_response(
        &self,
        object: domain::Object,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<domain::Object, Status> {
        self.resolve_computed_for_response_with_policy(object, principals, None, tenant_context)
    }

    pub(super) fn resolve_computed_for_response_with_policy(
        &self,
        mut object: domain::Object,
        principals: &[String],
        policy_context: Option<&crate::sekai::object_security::PrincipalPolicyContext>,
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<domain::Object, Status> {
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        compute::resolve_schema_computed_with_result_filter(
            &mut object,
            &self.db,
            &schema,
            |candidate| {
                if is_reserved_governance_kind(&candidate.kind)
                    || !object_is_visible(
                        &self.db,
                        &self.security,
                        candidate,
                        principals,
                        tenant_context,
                    )
                {
                    return Ok(false);
                }
                match policy_context {
                    Some(context) => Ok(self
                        .db
                        .get_object_with_policy_context(&candidate.id, context)?
                        .is_some_and(|authorized| authorized.updated == candidate.updated)),
                    None => Ok(true),
                }
            },
        )
        .map_err(Status::internal)?;
        let object = self
            .db
            .project_object_property_grants(object)
            .map_err(|error| {
                if error.starts_with("object_security_denied") {
                    Status::permission_denied("access denied")
                } else {
                    Status::unavailable("object authorization unavailable")
                }
            })?;
        Ok(redact_restricted_properties(
            object,
            &schema,
            &self.security,
            principals,
        ))
    }

    pub(super) fn resolve_computed_for_responses(
        &self,
        objects: Vec<domain::Object>,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<domain::Object>, Status> {
        self.resolve_computed_for_responses_with_policy(objects, principals, None, tenant_context)
    }

    pub(super) fn resolve_computed_for_responses_with_policy(
        &self,
        objects: Vec<domain::Object>,
        principals: &[String],
        policy_context: Option<&crate::sekai::object_security::PrincipalPolicyContext>,
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<domain::Object>, Status> {
        objects
            .into_iter()
            .map(|object| {
                self.resolve_computed_for_response_with_policy(
                    object,
                    principals,
                    policy_context,
                    tenant_context,
                )
            })
            .collect()
    }
}
