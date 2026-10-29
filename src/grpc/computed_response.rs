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
        purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    ) -> Result<domain::Object, Status> {
        self.resolve_computed_for_response_with_policy(
            object,
            principals,
            None,
            tenant_context,
            purpose,
        )
    }

    pub(super) fn resolve_computed_for_response_with_policy(
        &self,
        mut object: domain::Object,
        principals: &[String],
        policy_context: Option<&crate::sekai::object_security::PrincipalPolicyContext>,
        tenant_context: Option<&RequestEnterpriseContext>,
        purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    ) -> Result<domain::Object, Status> {
        object = self
            .db
            .runtime()
            .project_object_property_grants(object)
            .map_err(|error| {
                if error.starts_with("object_security_denied") {
                    Status::permission_denied("access denied")
                } else {
                    Status::unavailable("object authorization unavailable")
                }
            })?;
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        compute::resolve_schema_computed_with_result_filter(
            &mut object,
            self.db.runtime(),
            &schema,
            |candidate| {
                if is_reserved_governance_kind(&candidate.kind)
                    || !object_is_visible(
                        self.db.runtime(),
                        &self.security,
                        candidate,
                        principals,
                        tenant_context,
                    )
                {
                    return Ok(false);
                }
                if !purpose_kind_permitted(
                    self.db.runtime(),
                    &candidate.namespace,
                    &candidate.kind,
                    purpose,
                )
                .map_err(|status| status.to_string())?
                {
                    return Ok(false);
                }
                match policy_context {
                    Some(context) => Ok(self
                        .db
                        .runtime()
                        .get_object_with_policy_context(&candidate.id, context)?
                        .is_some_and(|authorized| authorized.updated == candidate.updated)),
                    None => Ok(true),
                }
            },
        )
        .map_err(|error| {
            if error.starts_with("object_security_denied") {
                Status::permission_denied("access denied")
            } else if error.contains("purpose authorization unavailable")
                || error.contains("object authorization unavailable")
            {
                Status::unavailable(error)
            } else {
                Status::internal(error)
            }
        })?;
        self.project_for_response(object, &schema, principals, tenant_context)
    }

    /// The properties of `object` a reader sees, without computing any: its
    /// property grants, then restricted properties redacted for the request's
    /// actor and for `principals`.
    pub(super) fn project_for_response(
        &self,
        object: domain::Object,
        schema: &crate::sekai::schema::SchemaRegistry,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<domain::Object, Status> {
        let mut object = self
            .db
            .runtime()
            .project_object_property_grants(object)
            .map_err(|error| {
                if error.starts_with("object_security_denied") {
                    Status::permission_denied("access denied")
                } else {
                    Status::unavailable("object authorization unavailable")
                }
            })?;
        if let Some(actor) = tenant_context.and_then(|context| context.act.as_ref()) {
            object = redact_restricted_properties(
                object,
                schema,
                &self.security,
                std::slice::from_ref(actor),
            );
        }
        Ok(redact_restricted_properties(
            object,
            schema,
            &self.security,
            principals,
        ))
    }

    pub(super) fn resolve_computed_for_responses_with_policy(
        &self,
        objects: Vec<domain::Object>,
        principals: &[String],
        policy_context: Option<&crate::sekai::object_security::PrincipalPolicyContext>,
        tenant_context: Option<&RequestEnterpriseContext>,
        purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    ) -> Result<Vec<domain::Object>, Status> {
        objects
            .into_iter()
            .map(|object| {
                self.resolve_computed_for_response_with_policy(
                    object,
                    principals,
                    policy_context,
                    tenant_context,
                    purpose,
                )
            })
            .collect()
    }
}
