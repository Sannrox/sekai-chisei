//! Shared computed-property response helpers for query, mutation, and retrieval.
//!
//! These are private implementation used by already-deep modules. They are not a
//! new ordered lifecycle.

use super::*;

impl SekaiServiceImpl {
    pub(super) fn resolve_computed_for_response(
        &self,
        mut object: domain::Object,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<domain::Object, Status> {
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        compute::resolve_schema_computed_with_filter(&mut object, &self.db, &schema, |candidate| {
            !is_reserved_governance_kind(&candidate.kind)
                && object_is_visible(
                    &self.db,
                    &self.security,
                    candidate,
                    principals,
                    tenant_context,
                )
        })
        .map_err(Status::internal)?;
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
        objects
            .into_iter()
            .map(|object| self.resolve_computed_for_response(object, principals, tenant_context))
            .collect()
    }
}
