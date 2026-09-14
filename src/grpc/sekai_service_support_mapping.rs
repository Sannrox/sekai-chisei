use super::*;

pub(super) fn read_limit_offset(limit: i32, offset: i32) -> Result<(i32, i32), Status> {
    if offset < 0 {
        return Err(Status::invalid_argument("offset must be >= 0"));
    }
    let effective_limit = if limit <= 0 {
        DEFAULT_LIST_LIMIT
    } else {
        limit.min(MAX_LIST_LIMIT)
    };
    Ok((effective_limit, offset))
}
pub(super) fn parse_property_operator(op: &str) -> Result<&'static str, Status> {
    match op.to_lowercase().as_str() {
        "eq" => Ok("eq"),
        "ne" | "neq" => Ok("ne"),
        "gt" => Ok("gt"),
        "gte" => Ok("gte"),
        "lt" => Ok("lt"),
        "lte" => Ok("lte"),
        "contains" => Ok("contains"),
        "prefix" => Ok("prefix"),
        "in" => Ok("in"),
        other => Err(Status::invalid_argument(format!(
            "unsupported property operator: {other}"
        ))),
    }
}
pub(super) fn parse_order_by(order_by: &str) -> Result<String, Status> {
    if order_by.is_empty() {
        return Ok(String::new());
    }
    let normalized = order_by.trim().to_lowercase();
    if normalized == "name" || normalized == "created" || normalized == "updated" {
        return Ok(normalized);
    }
    if let Some((prefix, key)) = order_by.trim().split_once(':') {
        if !prefix.eq_ignore_ascii_case("property") {
            return Err(Status::invalid_argument("unsupported order_by"));
        }
        if !domain::is_valid_property_key(key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        return Ok(format!("property:{}", key.trim()));
    }
    Err(Status::invalid_argument("unsupported order_by"))
}
pub(super) fn parse_list_filter(f: ListFilter) -> Result<domain::ListFilter, Status> {
    let (limit, offset) = read_limit_offset(f.limit, f.offset)?;
    let mut property_filters = Vec::new();
    for pf in f.property_filters {
        if !domain::is_valid_property_key(&pf.key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        property_filters.push(domain::PropertyFilter {
            key: pf.key,
            op: parse_property_operator(&pf.op)?.to_string(),
            value: pf.value,
        });
    }
    let interface_filter = parse_interface_filter(f.interface_filter)?;
    let order_by = parse_order_by(&f.order_by)?;
    Ok(domain::ListFilter {
        kind: if f.kind.is_empty() {
            None
        } else {
            Some(f.kind)
        },
        name: if f.name.is_empty() {
            None
        } else {
            Some(f.name)
        },
        namespace: if f.namespace.is_empty() {
            None
        } else {
            Some(f.namespace)
        },
        property_filters,
        interface_filter,
        limit,
        offset,
        order_by,
        descending: f.descending,
    })
}
pub(super) fn parse_interface_filter(interface_filter: Vec<String>) -> Result<Vec<String>, Status> {
    let mut parsed = Vec::new();
    for interface_name in interface_filter {
        if interface_name.trim().is_empty() {
            return Err(Status::invalid_argument("interface name required"));
        }
        parsed.push(interface_name);
    }
    Ok(parsed)
}
pub(super) fn to_proto_obj(o: &domain::Object) -> Object {
    Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}
pub(super) fn can_read_restricted_properties(
    security: &SecurityChecker,
    object: &domain::Object,
    principals: &[String],
) -> bool {
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
    {
        return true;
    }
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    security.can_admin(&object.id, &refs)
}
pub(super) fn redact_restricted_properties(
    mut object: domain::Object,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
) -> domain::Object {
    if can_read_restricted_properties(security, &object, principals) {
        return object;
    }
    let Some(object_type) = schema.get(&object.kind) else {
        return object;
    };
    for property in &object_type.properties {
        if schema::is_restricted_property_classification(&property.classification)
            && object.properties.contains_key(&property.name)
        {
            object
                .properties
                .insert(property.name.clone(), REDACTED_VALUE.to_string());
        }
    }
    object
}
pub(super) fn restricted_property_names_for_kind(
    schema: &schema::SchemaRegistry,
    kind: &str,
) -> std::collections::HashSet<String> {
    if kind.is_empty() {
        return schema
            .all()
            .iter()
            .flat_map(|object_type| {
                object_type
                    .properties
                    .iter()
                    .filter(|property| {
                        schema::is_restricted_property_classification(&property.classification)
                    })
                    .map(|property| property.name.clone())
                    .collect::<Vec<_>>()
            })
            .collect();
    }
    schema
        .get(kind)
        .map(|object_type| {
            object_type
                .properties
                .iter()
                .filter(|property| {
                    schema::is_restricted_property_classification(&property.classification)
                })
                .map(|property| property.name.clone())
                .collect()
        })
        .unwrap_or_default()
}
pub(super) fn principals_can_query_restricted_properties(principals: &[String]) -> bool {
    principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
}
pub(super) fn ensure_property_grant_query_allowed(
    db: &RuntimeDb,
    namespace: Option<&str>,
    kind: Option<&str>,
    properties: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), Status> {
    db.reject_ungranted_property_query(namespace, kind, properties)
        .map_err(|error| {
            if error.starts_with("object_security_denied") {
                Status::permission_denied("access denied")
            } else {
                Status::unavailable("object authorization unavailable")
            }
        })
}
pub(super) fn enforce_property_grant_mutation(
    db: &RuntimeDb,
    existing: Option<&domain::Object>,
    object: &mut domain::Object,
) -> Result<(), Status> {
    let Some(policy) = db
        .active_object_policy(&object.namespace, &object.kind)
        .map_err(|_| Status::unavailable("object authorization unavailable"))?
    else {
        return Ok(());
    };
    policy
        .apply_property_grant_mutation(existing, object)
        .map_err(|error| {
            if error.starts_with("object_security_denied") {
                Status::permission_denied("access denied")
            } else {
                Status::unavailable("object authorization unavailable")
            }
        })
}
pub(super) fn ensure_property_query_allowed(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    kind: &str,
    properties: impl IntoIterator<Item = String>,
) -> Result<(), Status> {
    if principals_can_query_restricted_properties(principals) {
        return Ok(());
    }
    let restricted = restricted_property_names_for_kind(schema, kind);
    if restricted.is_empty() {
        return Ok(());
    }
    if let Some(property) = properties
        .into_iter()
        .find(|property| restricted.contains(property))
    {
        return Err(Status::permission_denied(format!(
            "restricted property filter denied: {property}"
        )));
    }
    Ok(())
}
pub(super) fn queried_order_property(order_by: &str) -> Option<String> {
    order_by
        .strip_prefix("property:")
        .filter(|property| !property.is_empty())
        .map(ToOwned::to_owned)
}
pub(super) fn preserve_redacted_restricted_properties(
    db: &RuntimeDb,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
    object: &mut domain::Object,
) -> Result<(), Status> {
    if can_read_restricted_properties(security, object, principals) {
        return Ok(());
    }
    let Some(existing) = db.get_object(&object.id).map_err(Status::internal)? else {
        return Ok(());
    };
    let mut restricted = restricted_property_names_for_kind(schema, &object.kind);
    restricted.extend(restricted_property_names_for_kind(schema, &existing.kind));
    if object.kind != existing.kind
        && restricted
            .iter()
            .any(|property| existing.properties.contains_key(property))
    {
        return Err(Status::permission_denied(
            "restricted property mutation denied",
        ));
    }
    for property in restricted {
        if let Some(existing_value) = existing.properties.get(&property) {
            object.properties.insert(property, existing_value.clone());
        } else {
            object.properties.remove(&property);
        }
    }
    Ok(())
}
pub(super) fn ensure_restricted_create_properties_allowed(
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
    object: &domain::Object,
) -> Result<(), Status> {
    if can_read_restricted_properties(security, object, principals) {
        return Ok(());
    }
    let restricted = restricted_property_names_for_kind(schema, &object.kind);
    if let Some(property) = restricted.into_iter().find(|property| {
        object
            .properties
            .get(property)
            .is_some_and(|value| !value.is_empty())
    }) {
        return Err(Status::permission_denied(format!(
            "restricted property mutation denied: {property}"
        )));
    }
    Ok(())
}
pub(super) fn redact_object_change_values(
    change: audit::ObjectChange,
    object_id: &str,
    kind: &str,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
    policy: Option<&crate::sekai::object_security::ObjectSecurityPolicy>,
) -> ObjectChange {
    let object = domain::Object {
        id: object_id.into(),
        kind: kind.into(),
        name: String::new(),
        namespace: String::new(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 0,
        updated: 0,
    };
    let restricted = if can_read_restricted_properties(security, &object, principals) {
        std::collections::HashSet::new()
    } else {
        restricted_property_names_for_kind(schema, kind)
    };
    let should_redact = change
        .field
        .strip_prefix("properties.")
        .is_some_and(|property| {
            restricted.contains(property)
                || policy.is_some_and(|policy| {
                    !policy.allows_property_access(
                        property,
                        crate::sekai::object_security::PropertyGrantAccess::Read,
                    )
                })
        });
    ObjectChange {
        id: change.id,
        object_id: change.object_id,
        field: change.field,
        old_value: if should_redact {
            REDACTED_VALUE.into()
        } else {
            change.old_value
        },
        new_value: if should_redact {
            REDACTED_VALUE.into()
        } else {
            change.new_value
        },
        changed_by: change.changed_by,
        timestamp: change.timestamp,
        operation_id: String::new(),
    }
}
pub(super) fn to_proto_link(l: &domain::Link) -> Link {
    Link {
        id: l.id.clone(),
        from_id: l.from_id.clone(),
        to_id: l.to_id.clone(),
        relation: l.relation.clone(),
        created: l.created,
    }
}
pub(super) fn from_proto_obj(o: &Object) -> domain::Object {
    domain::Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}
pub(super) fn to_proto_schema_type(object_type: &schema::ObjectType) -> ObjectType {
    ObjectType {
        kind: object_type.kind.clone(),
        description: object_type.description.clone(),
        properties: object_type
            .properties
            .iter()
            .map(to_proto_property_def)
            .collect(),
        is_builtin: object_type.is_builtin,
        implements: object_type.implements.clone(),
    }
}
pub(super) fn to_proto_property_def(property: &schema::PropertyDef) -> PropertyDef {
    PropertyDef {
        name: property.name.clone(),
        r#type: property.prop_type.as_str().to_string(),
        required: property.required,
        description: property.description.clone(),
        enum_values: property.enum_values.clone(),
        link_kind: property.link_kind.clone(),
        compute_expr: property.compute_expr.clone(),
        classification: schema::normalize_property_classification(&property.classification)
            .to_string(),
        struct_fields: property
            .struct_fields
            .iter()
            .map(to_proto_struct_field_def)
            .collect(),
    }
}
pub(super) fn to_proto_struct_field_def(field: &schema::StructFieldDef) -> StructFieldDef {
    StructFieldDef {
        name: field.name.clone(),
        r#type: field.prop_type.as_str().to_string(),
        required: field.required,
        description: field.description.clone(),
        enum_values: field.enum_values.clone(),
    }
}
pub(super) fn from_proto_schema_type(
    object_type: &ObjectType,
) -> Result<schema::ObjectType, Status> {
    let properties = object_type
        .properties
        .iter()
        .map(from_proto_property_def)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(schema::ObjectType {
        kind: object_type.kind.clone(),
        description: object_type.description.clone(),
        properties,
        is_builtin: object_type.is_builtin,
        implements: object_type.implements.clone(),
    })
}
pub(super) fn from_proto_property_def(
    property: &PropertyDef,
) -> Result<schema::PropertyDef, Status> {
    let prop_type = schema::PropertyType::parse(&property.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown property type: {}", property.r#type))
    })?;
    Ok(schema::PropertyDef {
        name: property.name.clone(),
        prop_type,
        required: property.required,
        description: property.description.clone(),
        enum_values: property.enum_values.clone(),
        link_kind: property.link_kind.clone(),
        compute_expr: property.compute_expr.clone(),
        classification: schema::normalize_property_classification(&property.classification)
            .to_string(),
        struct_fields: property
            .struct_fields
            .iter()
            .map(from_proto_struct_field_def)
            .collect::<Result<Vec<_>, _>>()?,
    })
}
pub(super) fn from_proto_struct_field_def(
    field: &StructFieldDef,
) -> Result<schema::StructFieldDef, Status> {
    let prop_type = schema::PropertyType::parse(&field.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown struct field type: {}", field.r#type))
    })?;
    Ok(schema::StructFieldDef {
        name: field.name.clone(),
        prop_type,
        required: field.required,
        description: field.description.clone(),
        enum_values: field.enum_values.clone(),
    })
}
pub(super) fn ontology_class_object_id(name: &str) -> String {
    format!("ontology:class:{name}")
}
pub(super) fn ontology_relation_object_id(name: &str) -> String {
    format!("ontology:relation:{name}")
}
pub(super) fn check_ontology_admin(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("ontology", &refs)
        // Schema admins govern the object model the ontology projects from, so
        // they may administer the ontology as well.
        || security.can_admin("schema", &refs)
        || security.can_admin(object_id, &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("ontology admin required"))
}
pub(super) fn check_ontology_class_read(
    security: &SecurityChecker,
    class: &ontology::OntologyClass,
    principals: &[String],
) -> Result<(), Status> {
    check_read(security, &ontology_class_object_id(&class.name), principals)?;
    for reference in class
        .superclasses
        .iter()
        .chain(&class.equivalent_classes)
        .chain(&class.disjoint_classes)
    {
        check_read(security, &ontology_class_object_id(reference), principals)?;
    }
    Ok(())
}
pub(super) fn check_ontology_relation_read(
    security: &SecurityChecker,
    relation: &ontology::OntologyRelation,
    principals: &[String],
) -> Result<(), Status> {
    check_read(
        security,
        &ontology_relation_object_id(&relation.name),
        principals,
    )?;
    for endpoint in [&relation.domain, &relation.range] {
        check_read(security, &ontology_class_object_id(endpoint), principals)?;
    }
    if !relation.inverse.is_empty() {
        check_read(
            security,
            &ontology_relation_object_id(&relation.inverse),
            principals,
        )?;
    }
    Ok(())
}
pub(super) fn map_graph_mutation_error(error: String) -> Status {
    if error == "link endpoints violate ontology constraint"
        || error == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION
    {
        Status::failed_precondition(error)
    } else {
        Status::internal(error)
    }
}
pub(super) fn check_ontology_grant_target(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<bool, Status> {
    let exists = if let Some(name) = object_id.strip_prefix("ontology:class:") {
        db.get_ontology_class(name)
            .map_err(Status::internal)?
            .is_some()
    } else if let Some(name) = object_id.strip_prefix("ontology:relation:") {
        db.get_ontology_relation(name)
            .map_err(Status::internal)?
            .is_some()
    } else {
        return Ok(false);
    };
    if !exists {
        return Err(Status::not_found("grant target not found"));
    }
    check_ontology_admin(security, object_id, principals)?;
    Ok(true)
}
pub(super) fn to_proto_ontology_property(
    property: &ontology::OntologyProperty,
) -> OntologyProperty {
    OntologyProperty {
        name: property.name.clone(),
        r#type: property.prop_type.as_str().to_string(),
        required: property.required,
        description: property.description.clone(),
    }
}
pub(super) fn from_proto_ontology_property(
    property: &OntologyProperty,
) -> Result<ontology::OntologyProperty, Status> {
    let prop_type = schema::PropertyType::parse(&property.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown property type: {}", property.r#type))
    })?;
    Ok(ontology::OntologyProperty {
        name: property.name.clone(),
        prop_type,
        required: property.required,
        description: property.description.clone(),
    })
}
pub(super) fn to_proto_ontology_class(class: &ontology::OntologyClass) -> OntologyClass {
    OntologyClass {
        name: class.name.clone(),
        description: class.description.clone(),
        superclasses: class.superclasses.clone(),
        equivalent_classes: class.equivalent_classes.clone(),
        disjoint_classes: class.disjoint_classes.clone(),
        properties: class
            .properties
            .iter()
            .map(to_proto_ontology_property)
            .collect(),
        is_builtin: class.is_builtin,
        mapped_kind: class.mapped_kind.clone(),
    }
}
pub(super) fn from_proto_ontology_class(
    class: &OntologyClass,
) -> Result<ontology::OntologyClass, Status> {
    let properties = class
        .properties
        .iter()
        .map(from_proto_ontology_property)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ontology::OntologyClass {
        name: class.name.clone(),
        description: class.description.clone(),
        superclasses: class.superclasses.clone(),
        equivalent_classes: class.equivalent_classes.clone(),
        disjoint_classes: class.disjoint_classes.clone(),
        properties,
        is_builtin: class.is_builtin,
        mapped_kind: class.mapped_kind.clone(),
    })
}
pub(super) fn to_proto_ontology_relation(
    relation: &ontology::OntologyRelation,
) -> OntologyRelation {
    OntologyRelation {
        name: relation.name.clone(),
        description: relation.description.clone(),
        domain: relation.domain.clone(),
        range: relation.range.clone(),
        cardinality: Some(Cardinality {
            min: relation.cardinality.min,
            max: relation.cardinality.max,
        }),
        inverse: relation.inverse.clone(),
        transitive: relation.transitive,
        is_builtin: relation.is_builtin,
        mapped_relation: relation.mapped_relation.clone(),
    }
}
pub(super) fn from_proto_ontology_relation(
    relation: &OntologyRelation,
) -> Result<ontology::OntologyRelation, Status> {
    let cardinality = relation
        .cardinality
        .as_ref()
        .map(|cardinality| ontology::Cardinality {
            min: cardinality.min,
            max: cardinality.max,
        })
        .unwrap_or_default();
    Ok(ontology::OntologyRelation {
        name: relation.name.clone(),
        description: relation.description.clone(),
        domain: relation.domain.clone(),
        range: relation.range.clone(),
        cardinality,
        inverse: relation.inverse.clone(),
        transitive: relation.transitive,
        is_builtin: relation.is_builtin,
        mapped_relation: relation.mapped_relation.clone(),
    })
}
pub(super) fn schema_object_id(kind: &str) -> String {
    format!("schema:{kind}")
}
pub(super) fn action_object_id(name: &str) -> String {
    format!("action:{name}")
}
pub(super) fn is_reserved_governance_kind(kind: &str) -> bool {
    RESERVED_GOVERNANCE_KINDS.contains(&kind)
}
pub(super) fn action_work_lifecycle_status(error: ActionWorkLifecycleError) -> Status {
    match error {
        ActionWorkLifecycleError::InvalidArgument(message) => Status::invalid_argument(message),
        ActionWorkLifecycleError::FailedPrecondition(message) => {
            Status::failed_precondition(message)
        }
        ActionWorkLifecycleError::AlreadyExists(message) => Status::already_exists(message),
        ActionWorkLifecycleError::NotFound(message) => Status::not_found(message),
        ActionWorkLifecycleError::Internal(message) => Status::internal(message),
    }
}
pub(super) fn to_proto_attestation(a: &attestation::PolicyAttestation) -> PolicyAttestation {
    PolicyAttestation {
        id: a.id.clone(),
        decision_id: a.decision_id.clone(),
        policy_kind: a.policy_kind.clone(),
        policy_scope: a.policy_scope.clone(),
        policy_version: a.policy_version.clone(),
        policy_snapshot: a.policy_snapshot.clone(),
        inputs: a.inputs.clone(),
        decision: a.decision.clone(),
        content_hash: a.content_hash.clone(),
        created: a.created,
    }
}
pub(super) fn to_proto_action_policy(policy: &action_policy::ActionPolicy) -> ActionPolicy {
    ActionPolicy {
        scope: policy.scope.clone(),
        default_decision: policy.default_decision.as_str().to_string(),
        action_overrides: policy
            .action_overrides
            .iter()
            .map(|(name, decision)| (name.clone(), decision.as_str().to_string()))
            .collect(),
        risk_overrides: policy
            .risk_overrides
            .iter()
            .map(|(risk, decision)| (risk.as_str().to_string(), decision.as_str().to_string()))
            .collect(),
        max_mutations_per_work_unit: policy.max_mutations_per_work_unit.unwrap_or(0),
        max_deletes_per_work_unit: policy.max_deletes_per_work_unit.unwrap_or(0),
    }
}
pub(super) fn from_proto_action_policy(
    policy: &ActionPolicy,
) -> Result<action_policy::ActionPolicy, Status> {
    let scope = policy.scope.trim();
    if scope.is_empty() {
        return Err(Status::invalid_argument("policy scope required"));
    }
    let default_decision = ActionDecision::parse(&policy.default_decision)
        .ok_or_else(|| Status::invalid_argument("invalid or missing default_decision"))?;
    let mut action_overrides = HashMap::new();
    for (name, decision) in &policy.action_overrides {
        let decision = ActionDecision::parse(decision).ok_or_else(|| {
            Status::invalid_argument(format!("invalid decision for action {name}"))
        })?;
        action_overrides.insert(name.clone(), decision);
    }
    let mut risk_overrides = HashMap::new();
    for (risk, decision) in &policy.risk_overrides {
        let parsed_risk = RiskClass::parse(risk)
            .ok_or_else(|| Status::invalid_argument(format!("invalid risk class {risk}")))?;
        let decision = ActionDecision::parse(decision)
            .ok_or_else(|| Status::invalid_argument(format!("invalid decision for risk {risk}")))?;
        risk_overrides.insert(parsed_risk, decision);
    }
    Ok(action_policy::ActionPolicy {
        scope: scope.to_string(),
        default_decision,
        action_overrides,
        risk_overrides,
        max_mutations_per_work_unit: (policy.max_mutations_per_work_unit > 0)
            .then_some(policy.max_mutations_per_work_unit),
        max_deletes_per_work_unit: (policy.max_deletes_per_work_unit > 0)
            .then_some(policy.max_deletes_per_work_unit),
    })
}
pub(super) fn to_proto_dataset(d: &dataset::Dataset) -> Dataset {
    Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| ColumnDef {
                name: c.name.clone(),
                r#type: c.col_type.clone(),
                classification: c.classification.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}
pub(super) fn from_proto_dataset(d: &Dataset) -> dataset::Dataset {
    dataset::Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| dataset::ColumnDef {
                name: c.name.clone(),
                col_type: c.r#type.clone(),
                classification: c.classification.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}
pub(super) fn from_proto_row_filters(filters: &[RowFilter]) -> Vec<dataset::RowFilter> {
    filters
        .iter()
        .map(|f| dataset::RowFilter {
            column: f.column.clone(),
            op: f.op.clone(),
            value: f.value.clone(),
        })
        .collect()
}
pub(super) fn to_proto_virtual_table(vt: &dataset::VirtualTable) -> VirtualTable {
    VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: vt
            .filters
            .iter()
            .map(|f| RowFilter {
                column: f.column.clone(),
                op: f.op.clone(),
                value: f.value.clone(),
            })
            .collect(),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}
pub(super) fn from_proto_virtual_table(vt: &VirtualTable) -> dataset::VirtualTable {
    dataset::VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: from_proto_row_filters(&vt.filters),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}
pub(super) fn to_proto_function(f: &function::Function) -> Function {
    Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| FuncParam {
                name: p.name.clone(),
                r#type: p.param_type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                r#as: s.alias.clone(),
            })
            .collect(),
        created: f.created,
    }
}
pub(super) fn from_proto_function(f: &Function) -> function::Function {
    function::Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| function::FuncParam {
                name: p.name.clone(),
                param_type: p.r#type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| function::PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                alias: s.r#as.clone(),
            })
            .collect(),
        created: f.created,
    }
}
pub(super) fn to_proto_grant(g: &security::Grant) -> Grant {
    Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role: g.role.as_str().to_string(),
        created: g.created,
    }
}
pub(super) fn to_proto_contention_scope(scope: &coordination::ContentionScope) -> ContentionScope {
    ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}
pub(super) fn from_proto_contention_scope(
    scope: &ContentionScope,
) -> coordination::ContentionScope {
    coordination::ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}
pub(super) fn to_proto_work_unit(work_unit: &coordination::WorkUnit) -> WorkUnit {
    WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}
pub(super) fn from_proto_work_unit(work_unit: &WorkUnit) -> coordination::WorkUnit {
    coordination::WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}
pub(super) fn to_proto_reservation(reservation: &coordination::Reservation) -> Reservation {
    Reservation {
        id: reservation.id.clone(),
        work_unit_id: reservation.work_unit_id.clone(),
        scope_id: reservation.scope_id.clone(),
        status: reservation.status.clone(),
        lease_owner: reservation.lease_owner.clone(),
        leased_at: reservation.leased_at,
        expires_at: reservation.expires_at,
        released_at: reservation.released_at,
        created_at: reservation.created_at,
    }
}
pub(super) fn to_proto_run_event(event: &coordination::RunEvent) -> RunEvent {
    RunEvent {
        id: event.id.clone(),
        work_unit_id: event.work_unit_id.clone(),
        event_type: event.event_type.clone(),
        message: event.message.clone(),
        evidence: event.evidence.clone(),
        created_at: event.created_at,
    }
}
pub(super) fn from_proto_work_unit_filter(filter: &WorkUnitFilter) -> coordination::WorkUnitFilter {
    coordination::WorkUnitFilter {
        status: if filter.status.is_empty() {
            None
        } else {
            Some(filter.status.clone())
        },
        actor: if filter.actor.is_empty() {
            None
        } else {
            Some(filter.actor.clone())
        },
        scope_id: if filter.scope_id.is_empty() {
            None
        } else {
            Some(filter.scope_id.clone())
        },
        target_object_id: if filter.target_object_id.is_empty() {
            None
        } else {
            Some(filter.target_object_id.clone())
        },
        owner_principal: if filter.owner_principal.is_empty() {
            None
        } else {
            Some(filter.owner_principal.clone())
        },
        statuses: filter.statuses.clone(),
        created_after: filter.created_after,
        updated_after: filter.updated_after,
        creator_principal: if filter.creator_principal.is_empty() {
            None
        } else {
            Some(filter.creator_principal.clone())
        },
        page_token: if filter.page_token.is_empty() {
            None
        } else {
            Some(filter.page_token.clone())
        },
        limit: filter.limit,
        offset: filter.offset,
    }
}
pub(super) fn dedup_principal(principals: &[String]) -> String {
    principals.first().cloned().unwrap_or_default()
}
pub(super) fn trim_page<T>(items: &mut Vec<T>, limit: i32) {
    if limit > 0 && items.len() > limit as usize {
        items.truncate(limit as usize);
    }
}
pub(super) fn to_domain_handoff_reference(
    reference: &HandoffReference,
) -> handoff_domain::HandoffReference {
    handoff_domain::HandoffReference {
        kind: reference.kind.clone(),
        id: reference.id.clone(),
        version: reference.version.clone(),
        omitted: reference.omitted,
        omission_reason: reference.omission_reason.clone(),
    }
}
pub(super) fn to_proto_handoff_reference(
    reference: &handoff_domain::HandoffReference,
) -> HandoffReference {
    HandoffReference {
        kind: reference.kind.clone(),
        id: reference.id.clone(),
        version: reference.version.clone(),
        omitted: reference.omitted,
        omission_reason: reference.omission_reason.clone(),
    }
}
pub(super) fn to_proto_handoff(manifest: &handoff_domain::HandoffManifest) -> HandoffManifest {
    HandoffManifest {
        id: manifest.id.clone(),
        namespace: manifest.namespace.clone(),
        parent_operation_id: manifest.parent_operation_id.clone(),
        parent_attempt_id: manifest.parent_attempt_id.clone(),
        parent_work_unit_id: manifest.parent_work_unit_id.clone(),
        references: manifest
            .references
            .iter()
            .map(to_proto_handoff_reference)
            .collect(),
        creator_principal: manifest.creator_principal.clone(),
        intended_principal: manifest.intended_principal.clone(),
        intended_scope: manifest.intended_scope.clone(),
        purpose: manifest.purpose.clone(),
        created_at_ms: manifest.created_at_ms,
        expires_at_ms: manifest.expires_at_ms,
        digest: manifest.digest.clone(),
        supersedes_manifest_id: manifest.supersedes_manifest_id.clone(),
        revoked: manifest.revoked,
    }
}
pub(super) fn reference_content_digest(value: &impl serde::Serialize) -> Result<String, Status> {
    let bytes = serde_json::to_vec(value).map_err(|error| Status::internal(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}
pub(super) fn handoff_reference_available(
    service: &SekaiServiceImpl,
    reference: &handoff_domain::HandoffReference,
    namespace: &str,
    principals: &[String],
    now_ms: i64,
) -> Result<bool, Status> {
    let available = match reference.kind.as_str() {
        "operation_receipt" => {
            if let Some(receipt) = service
                .db
                .get_operation_receipt(&reference.id)
                .map_err(Status::internal)?
            {
                let version = reference_content_digest(&receipt)?;
                receipt.namespace == namespace
                    && version == reference.version
                    && principals.iter().any(|p| {
                        p == &receipt.initiating_actor || matches!(p.as_str(), "root" | "local")
                    })
            } else {
                false
            }
        }
        "work_unit" => service
            .db
            .get_work_unit(&reference.id)
            .map_err(Status::internal)?
            .is_some_and(|work_unit| {
                reference_content_digest(&work_unit).is_ok_and(|digest| digest == reference.version)
                    // Unbound work units have no namespace fact to match to the
                    // manifest. Owner readability alone must not widen scope.
                    && !work_unit.target_object_id.is_empty()
                    && service
                        .db
                        .get_object(&work_unit.target_object_id)
                        .is_ok_and(|object| {
                            object.is_some_and(|object| object.namespace == namespace)
                        })
                    && check_work_unit_read(&service.db, &service.security, &work_unit, principals)
                        .is_ok()
            }),
        "object" => service
            .db
            .get_object(&reference.id)
            .map_err(Status::internal)?
            .is_some_and(|object| {
                object.namespace == namespace
                    && reference_content_digest(&object)
                        .is_ok_and(|digest| digest == reference.version)
                    && check_team_namespace(&service.db, principals, namespace, false).is_ok()
                    && check_read(&service.security, &object.id, principals).is_ok()
            }),
        "evidence_submission" => {
            if let Some(submission) = service
                .db
                .get_evidence_submission(&reference.id)
                .map_err(Status::internal)?
            {
                let projected = service
                    .db
                    .get_evidence_projection_object_id(&reference.id)
                    .map_err(Status::internal)?;
                submission.namespace == namespace
                    && submission.content_digest == reference.version
                    && submission.lifecycle_state.is_usable()
                    && submission
                        .expires_at_ms
                        .is_none_or(|expiry| expiry > now_ms)
                    && projected
                        .is_some_and(|id| check_read(&service.security, &id, principals).is_ok())
            } else {
                false
            }
        }
        "kioku" => {
            let Ok(version) = reference.version.parse::<u32>() else {
                return Ok(false);
            };
            if let Some(memory) = service
                .db
                .get_kioku_memory(&reference.id, version)
                .map_err(Status::internal)?
            {
                memory.namespace == namespace
                    && memory.state == crate::chisei::kioku::MemoryLifecycleState::Active
                    && memory.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
                    && memory
                        .retention_until_ms
                        .is_none_or(|retention| retention > now_ms)
                    && principals.iter().any(|principal| {
                        service
                            .db
                            .kioku_authorized_classification_ceiling(namespace, principal)
                            .is_ok_and(|ceiling| memory.classification <= ceiling)
                    })
            } else {
                false
            }
        }
        _ => false,
    };
    Ok(available)
}
pub(super) fn map_handoff_lifecycle_error(error: HandoffLifecycleError) -> Status {
    match error {
        HandoffLifecycleError::InvalidArgument(message) => Status::invalid_argument(message),
        HandoffLifecycleError::AlreadyExists(message) => Status::already_exists(message),
        HandoffLifecycleError::FailedPrecondition(message) => Status::failed_precondition(message),
        HandoffLifecycleError::NotFound(message) => Status::not_found(message),
        HandoffLifecycleError::Storage(message) => Status::internal(message),
    }
}
pub(super) fn from_proto_grant(g: &Grant) -> Result<security::Grant, Status> {
    let role = security::Role::parse(&g.role).ok_or(Status::invalid_argument("invalid role"))?;
    Ok(security::Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role,
        created: g.created,
    })
}
pub(super) fn from_proto_context_root(
    root: ContextRoot,
) -> Result<retrieval::RetrievalRoot, Status> {
    let configured = [
        !root.object_id.is_empty(),
        !root.external_id.is_empty(),
        !root.link_id.is_empty(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();
    if configured != 1 {
        return Err(Status::invalid_argument(
            "each context root must set exactly one of object_id, external_id, or link_id",
        ));
    }
    if !root.object_id.is_empty() {
        Ok(retrieval::RetrievalRoot::Object(root.object_id))
    } else if !root.external_id.is_empty() {
        Ok(retrieval::RetrievalRoot::External(root.external_id))
    } else {
        Ok(retrieval::RetrievalRoot::Link(root.link_id))
    }
}
pub(super) fn map_retrieval_error(error: retrieval::RetrievalError) -> Status {
    match error {
        retrieval::RetrievalError::InvalidArgument(message) => Status::invalid_argument(message),
        retrieval::RetrievalError::Storage(message) => Status::internal(message),
    }
}
pub(super) fn map_lease_error(error: crate::sekai::lease::LeaseError) -> Status {
    use crate::sekai::lease::LeaseError;
    match error {
        LeaseError::Invalid(message) => Status::invalid_argument(message),
        LeaseError::Conflict(message) => Status::already_exists(message),
        LeaseError::Stale(message) => Status::failed_precondition(message),
        LeaseError::NotExpired => Status::failed_precondition("lease has not expired"),
        LeaseError::Storage(message) => Status::internal(message),
        LeaseError::Mutation(message) if message == "not found" => Status::not_found(message),
        LeaseError::Mutation(message) => Status::failed_precondition(message),
    }
}
pub(super) fn map_lease_lifecycle_error(error: LeaseLifecycleError) -> Status {
    match error {
        LeaseLifecycleError::InvalidArgument(message) => Status::invalid_argument(message),
        LeaseLifecycleError::FailedPrecondition(message) => Status::failed_precondition(message),
        LeaseLifecycleError::PermissionDenied(message) => Status::permission_denied(message),
        LeaseLifecycleError::NotFound(message) => Status::not_found(message),
        LeaseLifecycleError::Storage(message) => Status::internal(message),
        LeaseLifecycleError::Lease(error) => map_lease_error(error),
    }
}
pub(super) fn map_work_unit_lifecycle_error(error: WorkUnitLifecycleError) -> Status {
    match error {
        WorkUnitLifecycleError::NotFound(message) => Status::not_found(message),
        WorkUnitLifecycleError::PermissionDenied(message) => Status::permission_denied(message),
        WorkUnitLifecycleError::InvalidArgument(message) => Status::invalid_argument(message),
        WorkUnitLifecycleError::FailedPrecondition(message) => Status::failed_precondition(message),
        WorkUnitLifecycleError::AlreadyExists(message) => Status::already_exists(message),
        WorkUnitLifecycleError::Storage(message) => Status::internal(message),
    }
}
pub(super) fn transition_work_unit<'a>(
    db: &RuntimeDb,
    principals: &[String],
    work_unit_id: &str,
    request_id: &str,
    transition: WorkUnitTransition<'a>,
) -> Result<coordination::WorkUnit, Status> {
    let principal = dedup_principal(principals);
    WorkUnitLifecycle::new(db)
        .transition(TransitionWorkUnit {
            work_unit_id,
            request_id,
            principal: &principal,
            transition,
            now_ms: chrono::Utc::now().timestamp_millis(),
        })
        .map_err(map_work_unit_lifecycle_error)
}
pub(super) fn map_mutation_persistence_error(error: MutationPersistenceError) -> Status {
    match error {
        MutationPersistenceError::Graph(error) => map_graph_mutation_error(error),
        MutationPersistenceError::Lease(error) => map_lease_error(error),
        MutationPersistenceError::NotFound => Status::not_found("not found"),
        MutationPersistenceError::ChangedSinceAuthorization => {
            Status::failed_precondition(crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION)
        }
    }
}
pub(super) fn to_proto_lease(lease: &crate::sekai::lease::Lease) -> Lease {
    Lease {
        namespace: lease.namespace.clone(),
        key: lease.key.clone(),
        generation: lease.generation,
        fencing_token: lease.fencing_token.clone(),
        owner: lease.owner.clone(),
        status: lease.status.clone(),
        acquired_at_ms: lease.acquired_at_ms,
        refreshed_at_ms: lease.refreshed_at_ms,
        expires_at_ms: lease.expires_at_ms,
        released_at_ms: lease.released_at_ms,
        site_id: lease.site_id.clone(),
    }
}
