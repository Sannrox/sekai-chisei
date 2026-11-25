//! Read-time withholding by allowed egress (ADR 0164, #2699).
//!
//! `project_for_response` and Search remove values a reader may not receive,
//! query guards refuse filters and sorts that name them, and the read RPCs
//! that MCP dispatches to report them as `withheld_properties`. The data
//! class of a property is its schema classification.

use super::*;
use crate::composition::gateway_egress_policy::Disclosure;
use crate::sekai::object_security::PropertyGrantAccess;

impl SekaiServiceImpl {
    /// What a read may disclose: the strictest answer over the request's
    /// principals and, when delegated, its actor.
    pub(super) fn egress_disclosure(
        &self,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Disclosure {
        let actor = tenant_context.and_then(|context| context.act.as_deref());
        self.egress
            .disclosure(principals.iter().map(String::as_str).chain(actor))
    }

    /// Refuses a query naming a restricted property the readers may not
    /// filter on, or a property their allowed egress may not receive.
    pub(super) fn ensure_property_query_allowed(
        &self,
        schema: &schema::SchemaRegistry,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        kind: &str,
        properties: impl IntoIterator<Item = String>,
    ) -> Result<(), Status> {
        let properties = properties.into_iter().collect::<Vec<_>>();
        ensure_restricted_property_query_allowed(
            schema,
            principals,
            tenant_context,
            kind,
            properties.iter().cloned(),
        )?;
        let disclosure = self.egress_disclosure(principals, tenant_context);
        match properties
            .iter()
            .find(|property| !releases_property(&disclosure, schema, kind, property))
        {
            Some(property) => Err(Status::permission_denied(format!(
                "withheld property filter denied: {property}"
            ))),
            None => Ok(()),
        }
    }

    /// The properties of the returned `(namespace, kind)` pairs withheld from
    /// these readers, naming only properties their grants let them read.
    pub(super) fn withheld_properties<'a>(
        &self,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        kinds: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Vec<WithheldProperty>, Status> {
        let disclosure = self.egress_disclosure(principals, tenant_context);
        let Disclosure::Limited { reason, .. } = &disclosure else {
            return Ok(Vec::new());
        };
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        let mut withheld = std::collections::BTreeSet::new();
        for (namespace, kind) in kinds.into_iter().collect::<std::collections::BTreeSet<_>>() {
            let Some(object_type) = schema.get(kind) else {
                continue;
            };
            let policy = self
                .db
                .runtime()
                .active_object_policy(namespace, kind)
                .map_err(|_| Status::unavailable("object authorization unavailable"))?;
            for property in &object_type.properties {
                if !disclosure.releases(&property.classification)
                    && policy.as_ref().is_none_or(|policy| {
                        policy.allows_property_access(&property.name, PropertyGrantAccess::Read)
                    })
                {
                    withheld.insert((kind.to_string(), property.name.clone()));
                }
            }
        }
        Ok(withheld
            .into_iter()
            .map(|(kind, property)| WithheldProperty {
                kind,
                property,
                reason: reason.as_str().into(),
            })
            .collect())
    }
}

/// The `(namespace, kind)` of each object, for [`SekaiServiceImpl::withheld_properties`].
pub(super) fn kinds_of<'a>(
    objects: impl IntoIterator<Item = &'a Object>,
) -> impl Iterator<Item = (&'a str, &'a str)> {
    objects
        .into_iter()
        .map(|object| (object.namespace.as_str(), object.kind.as_str()))
}

/// `object` without the property values `disclosure` does not release.
pub(super) fn withhold_unreleased(
    mut object: domain::Object,
    schema: &schema::SchemaRegistry,
    disclosure: &Disclosure,
) -> domain::Object {
    if *disclosure != Disclosure::Unchecked {
        let kind = object.kind.clone();
        object
            .properties
            .retain(|property, _| releases_property(disclosure, schema, &kind, property));
    }
    object
}

/// Whether `disclosure` releases `property` of `kind`. With no kind, every
/// kind declaring the property must release it. An undeclared property has
/// the default classification.
pub(super) fn releases_property(
    disclosure: &Disclosure,
    schema: &schema::SchemaRegistry,
    kind: &str,
    property: &str,
) -> bool {
    if *disclosure == Disclosure::Unchecked {
        return true;
    }
    let all;
    let types = if kind.is_empty() {
        all = schema.all();
        all.iter().collect::<Vec<_>>()
    } else {
        schema.get(kind).into_iter().collect()
    };
    let declared = types
        .iter()
        .flat_map(|object_type| object_type.properties.iter())
        .filter(|declared| declared.name == property)
        .map(|declared| declared.classification.as_str())
        .collect::<Vec<_>>();
    if declared.is_empty() {
        disclosure.releases("")
    } else {
        declared.iter().all(|class| disclosure.releases(class))
    }
}
