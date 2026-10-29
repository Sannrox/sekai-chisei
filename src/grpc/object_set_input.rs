//! Object-set inputs of governed transforms, evaluated as a principal
//! (ADR 0140, #1977). The read path is `EvaluateObjectSet`'s: the same
//! authorization, the same marking and policy filter, and the same property
//! projection, read to the end instead of one page. Rows carry stored
//! properties, not computed ones.

use super::*;
use crate::sekai::governed_transform::{GovernedTransform, InputLoadBudget};
use crate::sekai::object_set::ObjectSetDescriptor as DomainObjectSetDescriptor;
use crate::sekai::object_set_input::{PinnedObjectSet, object_row};

/// Objects one object-set input may read; a larger set refuses the run.
pub(super) const MAX_OBJECT_SET_ROWS: usize = 10_000;

impl SekaiServiceImpl {
    /// Evaluates every object-set input of `transform` as `principals`,
    /// with the request's authenticated context when there is one. A kind or
    /// namespace they may not read refuses with `permission_denied`; objects
    /// they may not read are left out. The objects read are charged against
    /// the transform's input budget as they arrive, so a set too large for
    /// the run stops before it is read to the end.
    pub(super) fn evaluate_object_set_inputs(
        &self,
        transform: &GovernedTransform,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<PinnedObjectSet>, Status> {
        let mut budget = InputLoadBudget::for_preview(transform);
        transform
            .object_set_inputs()
            .into_iter()
            .map(|(alias, json)| {
                self.evaluate_object_set_input(
                    &alias,
                    &json,
                    principals,
                    tenant_context,
                    &mut budget,
                )
            })
            .collect()
    }

    fn evaluate_object_set_input(
        &self,
        alias: &str,
        json: &str,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        budget: &mut InputLoadBudget,
    ) -> Result<PinnedObjectSet, Status> {
        let descriptor = parse_descriptor(alias, json)?;
        let bound =
            self.authorize_domain_object_set_read(principals, tenant_context, descriptor)?;
        // Plain sets in this layer; aggregates, hops and traversals read
        // differently and wait for their own slice.
        if bound.descriptor.aggregation.is_some()
            || bound.descriptor.traversal.is_some()
            || !bound.descriptor.hops.is_empty()
        {
            return Err(Status::invalid_argument(format!(
                "input {alias}: object-set inputs read plain sets, without aggregation or traversal"
            )));
        }
        if self
            .db
            .runtime()
            .get_object_type_datasource(&bound.descriptor.namespace, &bound.descriptor.kind)
            .map_err(Status::internal)?
            .is_some()
        {
            return Err(Status::invalid_argument(format!(
                "input {alias}: object-set inputs over indexed object types are not available yet"
            )));
        }
        let policy_context = principal_policy_context_from(principals, tenant_context);
        // Restricted properties stay out of every reader's rows: their
        // classifications have no marking to carry them into the output.
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        let restricted = restricted_property_names_for_kind(&schema, &bound.descriptor.kind);
        // A filter on a restricted property would shape public output by
        // values no marking carries, so it is refused for every reader.
        if let Some(filter) = bound
            .filter
            .property_filters
            .iter()
            .find(|filter| restricted.contains(&filter.key))
        {
            return Err(Status::invalid_argument(format!(
                "input {alias}: object-set inputs may not filter on restricted property {}",
                filter.key
            )));
        }
        // One scan, charging each visible object as it arrives; the scan
        // stops at the input deadline, visible rows or not. Rows carry stored
        // properties as the reader sees them, not computed ones, whose
        // dependency reads and classifications this layer cannot bound. Each
        // marking is taken before projection, which may hide it from a reader.
        let deadline = budget.deadline();
        let mut too_many = false;
        let mut objects = Vec::new();
        let mut markings = HashMap::new();
        for_each_visible_object(
            self.db.runtime(),
            &bound.filter,
            principals,
            &policy_context,
            None,
            tenant_context,
            &mut |object| {
                if objects.len() >= MAX_OBJECT_SET_ROWS {
                    too_many = true;
                    return Ok(false);
                }
                markings.insert(
                    object.id.clone(),
                    crate::sekai::markings::object_marking_token(&object).map(str::to_string),
                );
                let mut object =
                    self.project_for_response(object, &schema, principals, tenant_context)?;
                object
                    .properties
                    .retain(|name, _| !restricted.contains(name));
                if !budget.charge(&object_row(&object)) {
                    return Ok(false);
                }
                objects.push(object);
                Ok(true)
            },
            &mut || std::time::Instant::now() < deadline,
        )?;
        budget.expire_if_past();
        if too_many {
            return Err(Status::resource_exhausted(format!(
                "input {alias}: object set exceeds {MAX_OBJECT_SET_ROWS} objects"
            )));
        }
        if let Some(exceeded) = budget.exceeded {
            return Err(Status::resource_exhausted(format!(
                "input {alias}: object set exceeds the input budget ({exceeded})"
            )));
        }
        let mut declared = self.declared_properties(&bound.descriptor)?;
        declared.retain(|name| !restricted.contains(name));
        Ok(PinnedObjectSet::from_objects(
            alias, &declared, &objects, &markings,
        ))
    }

    /// The properties the bound revision declares for the set's kind.
    fn declared_properties(
        &self,
        descriptor: &DomainObjectSetDescriptor,
    ) -> Result<Vec<String>, Status> {
        let members = self
            .db
            .runtime()
            .get_definition_members(&descriptor.namespace, &descriptor.definition_digest)
            .map_err(|_| Status::internal("definition revision unavailable"))?;
        Ok(members
            .iter()
            .find(|member| {
                member.member_kind == "object_type" && member.member_id == descriptor.kind
            })
            .map(crate::sekai::object_set::declared_property_names)
            .unwrap_or_default())
    }
}

fn parse_descriptor(alias: &str, json: &str) -> Result<DomainObjectSetDescriptor, Status> {
    serde_json::from_str(json).map_err(|_| {
        Status::invalid_argument(format!("input {alias}: object_set is not a descriptor"))
    })
}
