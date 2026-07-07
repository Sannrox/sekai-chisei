#![allow(clippy::result_large_err, clippy::collapsible_if, clippy::manual_clamp)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

use super::pb::sekai::sekai_service_server::SekaiService;
use super::pb::sekai::*;
use crate::db::sekai::SekaiDb;
use crate::domain;
use crate::sekai::action::{self, ActionExecutor};
use crate::sekai::action_approval;
use crate::sekai::action_policy::{self, ActionDecision};
use crate::sekai::schema::{self, SchemaRegistry};
use crate::sekai::security::SecurityChecker;
use crate::sekai::{audit, compute, coordination, dataset, function, security};
use uuid::Uuid;

const REDACTED_VALUE: &str = "[redacted]";

pub struct SekaiServiceImpl {
    db: Arc<SekaiDb>,
    actions: Arc<RwLock<ActionExecutor>>,
    security: Arc<SecurityChecker>,
    schema: Arc<RwLock<SchemaRegistry>>,
    schema_unavailable_error: Arc<RwLock<Option<String>>>,
    schema_load_errors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    budget: Option<Arc<crate::chisei::budget::BudgetTracker>>,
}

impl SekaiServiceImpl {
    pub fn new(db: Arc<SekaiDb>) -> Self {
        let security = Arc::new(SecurityChecker::new());
        let grants = db.list_all_grants().unwrap_or_default();
        security.load(&grants);
        let action_types = match db.list_action_types() {
            Ok(action_types) => action_types,
            Err(error) => {
                tracing::error!(%error, "failed to load action types");
                Vec::new()
            }
        };
        let actions = match ActionExecutor::from_action_types(action_types) {
            Ok(actions) => actions,
            Err(error) => {
                tracing::error!(%error, "failed to initialize action registry");
                ActionExecutor::new()
            }
        };
        let (types, schema_unavailable_error, schema_load_errors) =
            match db.list_object_types_with_errors() {
                Ok((types, errors)) => {
                    for (kind, error) in &errors {
                        tracing::error!(kind, %error, "failed to load schema type");
                    }
                    (types, None, errors)
                }
                Err(error) => {
                    tracing::error!(%error, "failed to load schema types");
                    (Vec::new(), Some(error), std::collections::HashMap::new())
                }
            };
        let interfaces = match db.list_interfaces() {
            Ok(interfaces) => interfaces,
            Err(error) => {
                tracing::error!(%error, "failed to load interfaces");
                Vec::new()
            }
        };
        let registry = SchemaRegistry::from_types_and_interfaces(types, interfaces);
        let schema = Arc::new(RwLock::new(registry));
        Self {
            db,
            actions: Arc::new(RwLock::new(actions)),
            security,
            schema,
            schema_unavailable_error: Arc::new(RwLock::new(schema_unavailable_error)),
            schema_load_errors: Arc::new(RwLock::new(schema_load_errors)),
            budget: None,
        }
    }

    /// Construct sharing a chisei budget tracker so governed actions can be
    /// metered against action-class budgets (Plan 9, Phase C).
    pub fn with_budget(
        db: Arc<SekaiDb>,
        budget: Arc<crate::chisei::budget::BudgetTracker>,
    ) -> Self {
        let mut svc = Self::new(db);
        svc.budget = Some(budget);
        svc
    }

    fn require_schema_kind_loaded(&self, kind: &str) -> Result<(), Status> {
        self.recover_schema_registry()?;
        let errors = self
            .schema_load_errors
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        if let Some(error) = errors.get(kind) {
            return Err(Status::internal(format!(
                "schema type {kind} unavailable: {error}"
            )));
        }
        Ok(())
    }

    /// Execute an action's effect (target auth + schema validation + mutation +
    /// audit) without policy gating. Used to resume an approved held action.
    /// `principals` are the identities re-checked for write access at execution
    /// time. Returns the executor's success message.
    fn run_action_effect(
        &self,
        action_name: &str,
        params: &HashMap<String, String>,
        actor: &str,
        principals: &[String],
    ) -> Result<String, Status> {
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(action_name);
        let sensitive_params = actions.sensitive_param_names(action_name);
        let target_ids = actions
            .target_ids(&self.db, action_name, params)
            .map_err(|err| {
                if mask_missing_link && err == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(err)
                }
            })?;
        for target_id in &target_ids {
            check_write(&self.security, target_id, principals)?;
        }
        let schema_kinds = actions
            .schema_kinds(&self.db, action_name, params)
            .map_err(Status::invalid_argument)?;
        for kind in schema_kinds {
            self.require_schema_kind_loaded(&kind)?;
        }
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        actions
            .validate_action_schema(action_name, &schema)
            .map_err(Status::invalid_argument)?;
        let schema_restricted_property =
            schema_restricted_action_property(&self.db, &schema, params);
        let msg = actions
            .execute(&self.db, &schema, action_name, params, actor)
            .map_err(Status::invalid_argument)?;
        drop(actions);
        drop(schema);
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor: actor.to_string(),
                action: action_name.to_string(),
                reason: "execute_action".into(),
                evidence: redact_action_evidence(
                    params,
                    &sensitive_params,
                    schema_restricted_property,
                ),
                target_id: target_ids.first().cloned().unwrap_or_default(),
                outcome: redact_action_outcome(
                    action_name,
                    params,
                    &msg,
                    schema_restricted_property,
                ),
            })
            .map_err(Status::internal)?;
        Ok(msg)
    }

    fn resolve_computed_for_response(
        &self,
        mut object: domain::Object,
        principals: &[String],
    ) -> Result<domain::Object, Status> {
        let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        compute::resolve_schema_computed_with_filter(&mut object, &self.db, &schema, |candidate| {
            self.security.can_access(&candidate.id, &refs)
        })
        .map_err(Status::internal)?;
        Ok(redact_restricted_properties(
            object,
            &schema,
            &self.security,
            principals,
        ))
    }

    fn resolve_computed_for_responses(
        &self,
        objects: Vec<domain::Object>,
        principals: &[String],
    ) -> Result<Vec<domain::Object>, Status> {
        objects
            .into_iter()
            .map(|object| self.resolve_computed_for_response(object, principals))
            .collect()
    }

    fn recover_schema_registry(&self) -> Result<(), Status> {
        let current_error = self
            .schema_unavailable_error
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        if current_error.is_none() {
            return Ok(());
        }

        match (
            self.db.list_object_types_with_errors(),
            self.db.list_interfaces(),
        ) {
            (Ok((types, errors)), Ok(interfaces)) => {
                for (kind, error) in &errors {
                    tracing::error!(kind, %error, "failed to load schema type");
                }
                *self
                    .schema
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? =
                    SchemaRegistry::from_types_and_interfaces(types, interfaces);
                *self
                    .schema_load_errors
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? = errors;
                *self
                    .schema_unavailable_error
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? = None;
                Ok(())
            }
            (Err(error), _) | (_, Err(error)) => {
                *self
                    .schema_unavailable_error
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? =
                    Some(error.clone());
                Err(Status::internal(format!(
                    "schema registry unavailable: {error}"
                )))
            }
        }
    }
}

fn caller_principals(req: &Request<impl std::any::Any>) -> Vec<String> {
    req.metadata()
        .get("x-principal")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["anonymous".to_string()])
}

fn work_unit_from_metadata(req: &Request<impl std::any::Any>) -> String {
    req.metadata()
        .get("x-chisei-work-unit")
        .or_else(|| req.metadata().get("x-chisei-task-id"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn require_authenticated(principals: &[String]) -> Result<(), Status> {
    if principals.is_empty() || principals.iter().all(|principal| principal == "anonymous") {
        return Err(Status::unauthenticated("principal required"));
    }
    Ok(())
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn redact_action_evidence(
    params: &std::collections::HashMap<String, String>,
    sensitive_params: &std::collections::HashSet<String>,
    schema_restricted_property: Option<bool>,
) -> std::collections::HashMap<String, String> {
    params
        .iter()
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            let sensitive_property = params
                .get("key")
                .or_else(|| params.get("property"))
                .map(|property| {
                    schema_restricted_property.unwrap_or_else(|| is_sensitive_name(property))
                })
                .unwrap_or(false);
            let value = if is_sensitive_name(&lower)
                || sensitive_params.contains(key)
                || ((lower == "value" || lower == "new_value") && sensitive_property)
            {
                "[redacted]".to_string()
            } else {
                value.clone()
            };
            (key.clone(), value)
        })
        .collect()
}

fn redact_action_outcome(
    action: &str,
    params: &std::collections::HashMap<String, String>,
    outcome: &str,
    schema_restricted_property: Option<bool>,
) -> String {
    if action == "set_property"
        && params
            .get("key")
            .map(|property| {
                schema_restricted_property.unwrap_or_else(|| is_sensitive_name(property))
            })
            .unwrap_or(false)
    {
        return format!(
            "set {}.{} = [redacted]",
            params.get("id").cloned().unwrap_or_default(),
            params.get("key").cloned().unwrap_or_default()
        );
    }
    outcome.to_string()
}

fn schema_restricted_action_property(
    db: &SekaiDb,
    schema: &schema::SchemaRegistry,
    params: &std::collections::HashMap<String, String>,
) -> Option<bool> {
    let property_name = params.get("key").or_else(|| params.get("property"))?;
    let object_id = params.get("id").or_else(|| params.get("object_id"))?;
    let object = db.get_object(object_id).ok().flatten()?;
    let object_type = schema.get(&object.kind)?;
    let property = object_type
        .properties
        .iter()
        .find(|property| property.name == *property_name)?;
    Some(schema::is_restricted_property_classification(
        &property.classification,
    ))
}

fn is_sensitive_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("passwd")
        || lower.contains("credential")
}

fn check_read(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_access(object_id, &refs) {
        return Err(Status::permission_denied("access denied"));
    }
    Ok(())
}

fn check_write(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_write(object_id, &refs) {
        return Err(Status::permission_denied("write denied"));
    }
    Ok(())
}

fn check_schema_admin(
    security: &SecurityChecker,
    kind: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("schema", &refs)
        || security.can_admin(&schema_object_id(kind), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("schema admin required"))
}

fn check_interface_admin(
    security: &SecurityChecker,
    name: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("schema", &refs)
        || security.can_admin(&interface_object_id(name), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("interface admin required"))
}

fn check_action_admin(
    security: &SecurityChecker,
    name: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("action", &refs)
        || security.can_admin(&action_object_id(name), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("action admin required"))
}

fn principal_matches(owner_principal: &str, principals: &[String]) -> bool {
    !owner_principal.is_empty()
        && principals
            .iter()
            .any(|principal| principal == owner_principal)
}

fn check_scope_read(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    if principal_matches(&scope.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("scope access denied"))
    }
}

fn check_scope_write(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    check_scope_read(scope, principals)
}

fn check_work_unit_read(
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_read(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit access denied"))
    }
}

fn check_work_unit_write(
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_write(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit write denied"))
    }
}

const DEFAULT_LIST_LIMIT: i32 = domain::DEFAULT_LIST_LIMIT;
const MAX_LIST_LIMIT: i32 = domain::MAX_LIST_LIMIT;

fn read_limit_offset(limit: i32, offset: i32) -> Result<(i32, i32), Status> {
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

fn parse_property_operator(op: &str) -> Result<&'static str, Status> {
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

fn parse_order_by(order_by: &str) -> Result<String, Status> {
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

fn parse_list_filter(f: ListFilter) -> Result<domain::ListFilter, Status> {
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

fn to_proto_object_set(set: &domain::ObjectSet) -> ObjectSet {
    ObjectSet {
        id: set.id.clone(),
        name: set.name.clone(),
        description: set.description.clone(),
        filter: Some(to_proto_list_filter(&set.filter)),
        owner_principal: set.owner_principal.clone(),
        created: set.created,
    }
}

fn to_proto_list_filter(filter: &domain::ListFilter) -> ListFilter {
    ListFilter {
        kind: filter.kind.clone().unwrap_or_default(),
        name: filter.name.clone().unwrap_or_default(),
        namespace: filter.namespace.clone().unwrap_or_default(),
        property_filters: filter
            .property_filters
            .iter()
            .map(|pf| PropertyFilter {
                key: pf.key.clone(),
                op: pf.op.clone(),
                value: pf.value.clone(),
            })
            .collect(),
        limit: filter.limit,
        offset: filter.offset,
        order_by: filter.order_by.clone(),
        descending: filter.descending,
        interface_filter: filter.interface_filter.clone(),
    }
}

fn parse_set_filter_from_request(input: &ObjectSet) -> Result<domain::ListFilter, Status> {
    let filter = input
        .filter
        .clone()
        .ok_or(Status::invalid_argument("filter required"))?;
    let mut property_filters = Vec::new();
    for pf in filter.property_filters {
        if !domain::is_valid_property_key(&pf.key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        property_filters.push(domain::PropertyFilter {
            key: pf.key,
            op: parse_property_operator(&pf.op)?.to_string(),
            value: pf.value,
        });
    }
    let interface_filter = parse_interface_filter(filter.interface_filter)?;
    if filter.offset < 0 {
        return Err(Status::invalid_argument("offset must be >= 0"));
    }
    let order_by = parse_order_by(&filter.order_by)?;
    Ok(domain::ListFilter {
        kind: if filter.kind.is_empty() {
            None
        } else {
            Some(filter.kind)
        },
        name: if filter.name.is_empty() {
            None
        } else {
            Some(filter.name)
        },
        namespace: if filter.namespace.is_empty() {
            None
        } else {
            Some(filter.namespace)
        },
        property_filters,
        interface_filter,
        // Keep zero/negative input as "use runtime request default" for resolves.
        // Callers should treat persisted ObjectSet filters as declarative query
        // descriptors, not already-paginated result sets.
        limit: if filter.limit <= 0 {
            0
        } else {
            filter.limit.min(MAX_LIST_LIMIT)
        },
        offset: filter.offset.max(0),
        order_by,
        descending: filter.descending,
    })
}

fn parse_interface_filter(interface_filter: Vec<String>) -> Result<Vec<String>, Status> {
    let mut parsed = Vec::new();
    for interface_name in interface_filter {
        if interface_name.trim().is_empty() {
            return Err(Status::invalid_argument("interface name required"));
        }
        parsed.push(interface_name);
    }
    Ok(parsed)
}

fn to_domain_object_set(
    input: ObjectSet,
    owner_principal: &str,
) -> Result<domain::ObjectSet, Status> {
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(Status::invalid_argument("name required"));
    }
    let requested_owner = input.owner_principal.clone();
    if !requested_owner.is_empty() && requested_owner != owner_principal {
        return Err(Status::invalid_argument("owner_principal mismatch"));
    }

    let filter = parse_set_filter_from_request(&input)?;
    let created = if input.created > 0 {
        input.created
    } else {
        now_millis()
    };
    let id = if input.id.is_empty() {
        format!("set-{}", Uuid::new_v4().simple())
    } else {
        input.id
    };
    Ok(domain::ObjectSet {
        id,
        name,
        description: input.description,
        filter,
        owner_principal: if requested_owner.is_empty() {
            owner_principal.to_string()
        } else {
            requested_owner
        },
        created,
    })
}

fn to_proto_obj(o: &domain::Object) -> Object {
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

fn can_read_restricted_properties(
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

fn redact_restricted_properties(
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

fn restricted_property_names_for_kind(
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

fn principals_can_query_restricted_properties(principals: &[String]) -> bool {
    principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
}

fn ensure_property_query_allowed(
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

fn ensure_list_filter_query_allowed(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    filter: &domain::ListFilter,
) -> Result<(), Status> {
    let mut queried_properties = filter
        .property_filters
        .iter()
        .map(|property_filter| property_filter.key.clone())
        .collect::<Vec<_>>();
    if let Some(order_property) = queried_order_property(&filter.order_by) {
        queried_properties.push(order_property);
    }
    ensure_property_query_allowed(
        schema,
        principals,
        filter.kind.as_deref().unwrap_or_default(),
        queried_properties,
    )
}

fn queried_order_property(order_by: &str) -> Option<String> {
    order_by
        .strip_prefix("property:")
        .filter(|property| !property.is_empty())
        .map(ToOwned::to_owned)
}

fn preserve_redacted_restricted_properties(
    db: &SekaiDb,
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

fn ensure_restricted_create_properties_allowed(
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

fn ensure_function_allows_restricted_properties(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    function: &function::Function,
) -> Result<(), Status> {
    for step in &function.pipeline {
        match step.op.as_str() {
            "filter" if !step.property.is_empty() => {
                ensure_property_query_allowed(
                    schema,
                    principals,
                    &step.kind,
                    [step.property.clone()],
                )?;
            }
            "aggregate" | "transform" if !step.field.is_empty() => {
                ensure_property_query_allowed(schema, principals, "", [step.field.clone()])?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn redact_object_change_values(
    change: audit::ObjectChange,
    object_id: &str,
    kind: &str,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
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
        .is_some_and(|property| restricted.contains(property));
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
    }
}

fn to_proto_link(l: &domain::Link) -> Link {
    Link {
        id: l.id.clone(),
        from_id: l.from_id.clone(),
        to_id: l.to_id.clone(),
        relation: l.relation.clone(),
        created: l.created,
    }
}

fn from_proto_obj(o: &Object) -> domain::Object {
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

fn to_proto_schema_type(object_type: &schema::ObjectType) -> ObjectType {
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

fn to_proto_interface(interface: &schema::InterfaceDef) -> InterfaceDef {
    InterfaceDef {
        name: interface.name.clone(),
        description: interface.description.clone(),
        properties: interface
            .properties
            .iter()
            .map(to_proto_property_def)
            .collect(),
        is_builtin: interface.is_builtin,
    }
}

fn to_proto_property_def(property: &schema::PropertyDef) -> PropertyDef {
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

fn to_proto_struct_field_def(field: &schema::StructFieldDef) -> StructFieldDef {
    StructFieldDef {
        name: field.name.clone(),
        r#type: field.prop_type.as_str().to_string(),
        required: field.required,
        description: field.description.clone(),
        enum_values: field.enum_values.clone(),
    }
}

fn from_proto_schema_type(object_type: &ObjectType) -> Result<schema::ObjectType, Status> {
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

fn from_proto_interface(interface: &InterfaceDef) -> Result<schema::InterfaceDef, Status> {
    let properties = interface
        .properties
        .iter()
        .map(from_proto_property_def)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(schema::InterfaceDef {
        name: interface.name.clone(),
        description: interface.description.clone(),
        properties,
        is_builtin: interface.is_builtin,
    })
}

fn from_proto_property_def(property: &PropertyDef) -> Result<schema::PropertyDef, Status> {
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

fn from_proto_struct_field_def(field: &StructFieldDef) -> Result<schema::StructFieldDef, Status> {
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

fn schema_object_id(kind: &str) -> String {
    format!("schema:{kind}")
}

fn interface_object_id(name: &str) -> String {
    format!("interface:{name}")
}

fn action_object_id(name: &str) -> String {
    format!("action:{name}")
}

/// Resolve the namespace used for action-policy scope resolution: prefer the
/// namespace of an existing target object, falling back to a `namespace` param
/// (used by `create_object` before the object exists).
fn action_policy_namespace(
    db: &SekaiDb,
    target_ids: &[String],
    params: &std::collections::HashMap<String, String>,
) -> String {
    for id in target_ids {
        if let Ok(Some(object)) = db.get_object(id)
            && !object.namespace.trim().is_empty()
        {
            return object.namespace;
        }
    }
    params
        .get("namespace")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
}

fn to_proto_action_approval(approval: &action_approval::ActionApproval) -> ActionApproval {
    ActionApproval {
        id: approval.id.clone(),
        status: approval.status.as_str().to_string(),
        actor: approval.actor.clone(),
        action: approval.action.clone(),
        params: approval.redacted_params(),
        work_unit: approval.work_unit.clone(),
        policy_scope: approval.policy_scope.clone(),
        risk_class: approval.risk_class.clone(),
        target_id: approval.target_id.clone(),
        created: approval.created,
        updated: approval.updated,
        decided_by: approval.decided_by.clone(),
        outcome: approval.outcome.clone(),
    }
}

fn to_proto_action_policy(policy: &action_policy::ActionPolicy) -> ActionPolicy {
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

fn from_proto_action_policy(policy: &ActionPolicy) -> Result<action_policy::ActionPolicy, Status> {
    let scope = policy.scope.trim();
    if scope.is_empty() {
        return Err(Status::invalid_argument("policy scope required"));
    }
    let default_decision = if policy.default_decision.trim().is_empty() {
        ActionDecision::Allow
    } else {
        ActionDecision::parse(&policy.default_decision)
            .ok_or_else(|| Status::invalid_argument("invalid default_decision"))?
    };
    let mut action_overrides = HashMap::new();
    for (name, decision) in &policy.action_overrides {
        let decision = ActionDecision::parse(decision).ok_or_else(|| {
            Status::invalid_argument(format!("invalid decision for action {name}"))
        })?;
        action_overrides.insert(name.clone(), decision);
    }
    let mut risk_overrides = HashMap::new();
    for (risk, decision) in &policy.risk_overrides {
        let parsed_risk = action::RiskClass::parse(risk)
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

fn to_proto_action_type(action_type: &action::ActionTypeDef) -> ActionTypeDef {
    ActionTypeDef {
        name: action_type.name.clone(),
        description: action_type.description.clone(),
        params: action_type
            .params
            .iter()
            .map(to_proto_action_param)
            .collect(),
        ops: action_type.ops.iter().map(to_proto_action_op).collect(),
        target_kind: action_type.target_kind.clone(),
        created: action_type.created,
    }
}

fn to_proto_action_param(param: &action::ActionParamDef) -> ActionParamDef {
    ActionParamDef {
        name: param.name.clone(),
        r#type: param.param_type.as_str().to_string(),
        required: param.required,
        enum_values: param.enum_values.clone(),
    }
}

fn to_proto_action_op(op: &action::ActionOp) -> ActionOp {
    ActionOp {
        op: op.op.clone(),
        property: op.property.clone(),
        value_from: op.value_from.clone(),
        relation: op.relation.clone(),
    }
}

fn from_proto_action_type(action_type: &ActionTypeDef) -> Result<action::ActionTypeDef, Status> {
    let params = action_type
        .params
        .iter()
        .map(from_proto_action_param)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(action::ActionTypeDef {
        name: action_type.name.clone(),
        description: action_type.description.clone(),
        params,
        ops: action_type.ops.iter().map(from_proto_action_op).collect(),
        target_kind: action_type.target_kind.clone(),
        created: action_type.created,
    })
}

fn from_proto_action_param(param: &ActionParamDef) -> Result<action::ActionParamDef, Status> {
    let param_type = schema::PropertyType::parse(&param.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown action param type: {}", param.r#type))
    })?;
    Ok(action::ActionParamDef {
        name: param.name.clone(),
        param_type,
        required: param.required,
        enum_values: param.enum_values.clone(),
    })
}

fn from_proto_action_op(op: &ActionOp) -> action::ActionOp {
    action::ActionOp {
        op: op.op.clone(),
        property: op.property.clone(),
        value_from: op.value_from.clone(),
        relation: op.relation.clone(),
    }
}

fn validate_action_type_against_schema(
    action_type: &action::ActionTypeDef,
    schema: &SchemaRegistry,
) -> Result<(), Status> {
    action::validate_action_type_against_schema(action_type, schema)
        .map_err(Status::invalid_argument)
}

fn validate_computed_property_functions(
    db: &SekaiDb,
    object_type: &schema::ObjectType,
) -> Result<(), Status> {
    for property in &object_type.properties {
        if property.prop_type != schema::PropertyType::Computed || property.compute_expr.is_empty()
        {
            continue;
        }
        if db
            .get_function(&property.compute_expr)
            .map_err(Status::internal)?
            .is_none()
        {
            return Err(Status::invalid_argument(format!(
                "computed property {} references unknown function {}",
                property.name, property.compute_expr
            )));
        }
    }
    Ok(())
}

fn to_proto_dataset(d: &dataset::Dataset) -> Dataset {
    Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| ColumnDef {
                name: c.name.clone(),
                r#type: c.col_type.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_dataset(d: &Dataset) -> dataset::Dataset {
    dataset::Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| dataset::ColumnDef {
                name: c.name.clone(),
                col_type: c.r#type.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_row_filters(filters: &[RowFilter]) -> Vec<dataset::RowFilter> {
    filters
        .iter()
        .map(|f| dataset::RowFilter {
            column: f.column.clone(),
            op: f.op.clone(),
            value: f.value.clone(),
        })
        .collect()
}

fn to_proto_virtual_table(vt: &dataset::VirtualTable) -> VirtualTable {
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

fn from_proto_virtual_table(vt: &VirtualTable) -> dataset::VirtualTable {
    dataset::VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: from_proto_row_filters(&vt.filters),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}

fn to_proto_function(f: &function::Function) -> Function {
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

fn from_proto_function(f: &Function) -> function::Function {
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

fn to_proto_grant(g: &security::Grant) -> Grant {
    Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role: g.role.as_str().to_string(),
        created: g.created,
    }
}

fn to_proto_contention_scope(scope: &coordination::ContentionScope) -> ContentionScope {
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

fn from_proto_contention_scope(scope: &ContentionScope) -> coordination::ContentionScope {
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

fn to_proto_work_unit(work_unit: &coordination::WorkUnit) -> WorkUnit {
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

fn from_proto_work_unit(work_unit: &WorkUnit) -> coordination::WorkUnit {
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

fn to_proto_reservation(reservation: &coordination::Reservation) -> Reservation {
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

fn to_proto_run_event(event: &coordination::RunEvent) -> RunEvent {
    RunEvent {
        id: event.id.clone(),
        work_unit_id: event.work_unit_id.clone(),
        event_type: event.event_type.clone(),
        message: event.message.clone(),
        evidence: event.evidence.clone(),
        created_at: event.created_at,
    }
}

fn from_proto_work_unit_filter(filter: &WorkUnitFilter) -> coordination::WorkUnitFilter {
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

fn to_proto_snapshot(snapshot: &coordination::CoordinationSnapshot) -> CoordinationSnapshot {
    CoordinationSnapshot {
        pending_count: snapshot.pending_count,
        running_count: snapshot.running_count,
        stale_count: snapshot.stale_count,
        active_reservation_count: snapshot.active_reservation_count,
        oldest_pending_age_ms: snapshot.oldest_pending_age_ms,
        oldest_running_age_ms: snapshot.oldest_running_age_ms,
        stale_reservation_count: snapshot.stale_reservation_count,
        blocked_scopes: snapshot
            .blocked_scopes
            .iter()
            .map(|scope| ScopeBlockage {
                scope_id: scope.scope_id.clone(),
                scope_name: scope.scope_name.clone(),
                reason: scope.reason.clone(),
                pending_count: scope.pending_count,
                active_count: scope.active_count,
            })
            .collect(),
    }
}

fn dedup_principal(principals: &[String]) -> String {
    principals.first().cloned().unwrap_or_default()
}

fn trim_page<T>(items: &mut Vec<T>, limit: i32) {
    if limit > 0 && items.len() > limit as usize {
        items.truncate(limit as usize);
    }
}

fn initialize_work_unit_for_create(work_unit: &mut coordination::WorkUnit, principal: &str) {
    if work_unit.owner_principal.is_empty() {
        work_unit.owner_principal = principal.into();
    }
    if work_unit.creator_principal.is_empty() {
        work_unit.creator_principal = principal.into();
    }
    work_unit.status = coordination::WORK_UNIT_STATUS_PENDING.into();
    work_unit.admitted_at = 0;
    work_unit.started_at = 0;
    work_unit.finished_at = 0;
    work_unit.last_heartbeat_at = 0;
    work_unit.failure_reason.clear();
    work_unit.cancel_reason.clear();
    work_unit.updated_at = work_unit.created_at;
}

fn aggregate_reconcile_summary(
    summary: &mut coordination::ReconcileSummary,
    next: coordination::ReconcileSummary,
) {
    summary.work_units_reconciled += next.work_units_reconciled;
    summary.reservations_released += next.reservations_released;
    summary.details.extend(next.details);
}

fn reconcile_owned_scope(
    db: &SekaiDb,
    now_ms: i64,
    scope_id: String,
    dry_run: bool,
    limit: i32,
    summary: &mut coordination::ReconcileSummary,
) -> Result<(), Status> {
    if limit > 0 && summary.work_units_reconciled >= limit {
        return Ok(());
    }
    let remaining = if limit > 0 {
        limit - summary.work_units_reconciled
    } else {
        0
    };
    let next = db
        .reconcile_work_units(
            now_ms,
            &coordination::ReconcileFilter {
                dry_run,
                work_unit_id: None,
                scope_id: Some(scope_id),
                limit: remaining,
            },
        )
        .map_err(Status::internal)?;
    aggregate_reconcile_summary(summary, next);
    Ok(())
}

fn from_proto_grant(g: &Grant) -> Result<security::Grant, Status> {
    let role = security::Role::parse(&g.role).ok_or(Status::invalid_argument("invalid role"))?;
    Ok(security::Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role,
        created: g.created,
    })
}

#[tonic::async_trait]
impl SekaiService for SekaiServiceImpl {
    async fn create_object(
        &self,
        req: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if obj.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        check_write(&self.security, &obj.id, &principals)?;
        let domain_obj = from_proto_obj(&obj);
        self.require_schema_kind_loaded(&domain_obj.kind)?;
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        schema
            .validate(&domain_obj)
            .map_err(Status::invalid_argument)?;
        ensure_restricted_create_properties_allowed(
            &schema,
            &self.security,
            &principals,
            &domain_obj,
        )?;
        drop(schema);
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .create_object_with_audit(&domain_obj, actor)
            .map_err(Status::internal)?;
        let domain_obj = self.resolve_computed_for_response(domain_obj, &principals)?;
        Ok(Response::new(CreateObjectResponse {
            object: Some(to_proto_obj(&domain_obj)),
        }))
    }
    async fn get_object(
        &self,
        req: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let id = req.into_inner().id;
        check_read(&self.security, &id, &principals)?;
        let obj = self
            .db
            .get_object(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let obj = self.resolve_computed_for_response(obj, &principals)?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn update_object(
        &self,
        req: Request<UpdateObjectRequest>,
    ) -> Result<Response<UpdateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if obj.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        check_write(&self.security, &obj.id, &principals)?;
        let mut domain_obj = from_proto_obj(&obj);
        self.require_schema_kind_loaded(&domain_obj.kind)?;
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        preserve_redacted_restricted_properties(
            &self.db,
            &schema,
            &self.security,
            &principals,
            &mut domain_obj,
        )?;
        schema
            .validate(&domain_obj)
            .map_err(Status::invalid_argument)?;
        drop(schema);
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .update_object_with_audit(&domain_obj, actor)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let domain_obj = self.resolve_computed_for_response(domain_obj, &principals)?;
        Ok(Response::new(UpdateObjectResponse {
            object: Some(to_proto_obj(&domain_obj)),
        }))
    }
    async fn delete_object(
        &self,
        req: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let id = req.into_inner().id;
        check_write(&self.security, &id, &principals)?;
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .delete_object_with_audit(&id, actor)
            .map_err(Status::internal)?;
        Ok(Response::new(DeleteObjectResponse {}))
    }
    async fn list_objects(
        &self,
        req: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let filter = parse_list_filter(req.into_inner().filter.unwrap_or_default())?;
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            let mut queried_properties = filter
                .property_filters
                .iter()
                .map(|property_filter| property_filter.key.clone())
                .collect::<Vec<_>>();
            if let Some(order_property) = queried_order_property(&filter.order_by) {
                queried_properties.push(order_property);
            }
            ensure_property_query_allowed(
                &schema,
                &principals,
                filter.kind.as_deref().unwrap_or_default(),
                queried_properties,
            )?;
        }
        // The API now defaults paging at 100 rows when no limit is provided;
        // DB callers using list_objects(&filter) remain unchanged.
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        // Query visibility in SQL so list pagination and totals honor grants
        // consistently across callers.
        let (objects, total) = self
            .db
            .list_objects_with_total_for_principals(&filter, &principal_refs)
            .map_err(Status::internal)?;
        let objects = self.resolve_computed_for_responses(objects, &principals)?;
        Ok(Response::new(ListObjectsResponse {
            objects: objects.iter().map(to_proto_obj).collect(),
            total,
        }))
    }
    async fn find_by_external_id(
        &self,
        req: Request<FindByExternalIdRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let external_id = req.into_inner().external_id;
        let obj = self
            .db
            .find_by_external_id(&external_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        check_read(&self.security, &obj.id, &principals)?;
        let obj = self.resolve_computed_for_response(obj, &principals)?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn find_by_property(
        &self,
        req: Request<FindByPropertyRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_property_query_allowed(&schema, &principals, &r.kind, [r.key.clone()])?;
        }
        let objs = self
            .db
            .find_by_property(&r.kind, &r.key, &r.value)
            .map_err(Status::internal)?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let filtered = self.security.filter_objects(&objs, &refs);
        let filtered = self
            .resolve_computed_for_responses(filtered.into_iter().cloned().collect(), &principals)?;
        Ok(Response::new(ListObjectsResponse {
            objects: filtered.iter().map(to_proto_obj).collect(),
            total: filtered.len() as i32,
        }))
    }
    async fn create_object_set(
        &self,
        req: Request<CreateObjectSetRequest>,
    ) -> Result<Response<CreateObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let owner = principals.first().cloned().unwrap_or_default();
        let domain_set = to_domain_object_set(
            req.into_inner()
                .object_set
                .ok_or(Status::invalid_argument("object_set required"))?,
            owner.as_str(),
        )?;
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_list_filter_query_allowed(&schema, &principals, &domain_set.filter)?;
        }
        self.db.create_object_set(&domain_set).map_err(|e| {
            let duplicate_name = e.starts_with("UNIQUE constraint failed:")
                && e.contains("sekai_object_sets.owner_principal")
                && e.contains("sekai_object_sets.name");
            let duplicate_id =
                e.starts_with("UNIQUE constraint failed:") && e.contains("sekai_object_sets.id");
            if duplicate_name || duplicate_id {
                Status::already_exists("object set already exists")
            } else {
                Status::internal(e)
            }
        })?;
        Ok(Response::new(CreateObjectSetResponse {
            object_set: Some(to_proto_object_set(&domain_set)),
        }))
    }
    async fn list_object_sets(
        &self,
        req: Request<ListObjectSetsRequest>,
    ) -> Result<Response<ListObjectSetsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let sets = self
            .db
            .list_object_sets_for_principals(&principal_refs)
            .map_err(Status::internal)?
            .into_iter()
            .collect::<Vec<_>>();
        Ok(Response::new(ListObjectSetsResponse {
            object_sets: sets.iter().map(to_proto_object_set).collect(),
        }))
    }
    async fn delete_object_set(
        &self,
        req: Request<DeleteObjectSetRequest>,
    ) -> Result<Response<DeleteObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        if id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        if self
            .db
            .delete_object_set_for_principals(&id, &principal_refs)
            .map_err(Status::internal)?
        {
            return Ok(Response::new(DeleteObjectSetResponse {}));
        }
        Err(Status::not_found("not found"))
    }
    async fn resolve_object_set(
        &self,
        req: Request<ResolveObjectSetRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let set = self
            .db
            .get_object_set(&inner.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        if !principal_matches(&set.owner_principal, &principals) {
            return Err(Status::not_found("not found"));
        }
        let mut filter = set.filter.clone();
        let (limit, _) = read_limit_offset(inner.limit, 0)?;
        if inner.limit > 0 || filter.limit <= 0 {
            filter.limit = limit;
        }
        if let Some(offset) = inner.offset {
            if offset < 0 {
                return Err(Status::invalid_argument("offset must be >= 0"));
            }
            filter.offset = offset;
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_list_filter_query_allowed(&schema, &principals, &filter)?;
        }
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let (objects, total) = self
            .db
            .list_objects_with_total_for_principals(&filter, &principal_refs)
            .map_err(Status::internal)?;
        let objects = self.resolve_computed_for_responses(objects, &principals)?;
        Ok(Response::new(ListObjectsResponse {
            objects: objects.iter().map(to_proto_obj).collect(),
            total,
        }))
    }
    async fn create_link(
        &self,
        req: Request<CreateLinkRequest>,
    ) -> Result<Response<CreateLinkResponse>, Status> {
        let l = req
            .into_inner()
            .link
            .ok_or(Status::invalid_argument("link required"))?;
        let dl = domain::Link {
            id: l.id.clone(),
            from_id: l.from_id.clone(),
            to_id: l.to_id.clone(),
            relation: l.relation.clone(),
            created: l.created,
        };
        self.db.create_link(&dl).map_err(Status::internal)?;
        Ok(Response::new(CreateLinkResponse { link: Some(l) }))
    }
    async fn delete_link(
        &self,
        req: Request<DeleteLinkRequest>,
    ) -> Result<Response<DeleteLinkResponse>, Status> {
        self.db
            .delete_link(&req.into_inner().id)
            .map_err(Status::internal)?;
        Ok(Response::new(DeleteLinkResponse {}))
    }
    async fn get_links(
        &self,
        req: Request<GetLinksRequest>,
    ) -> Result<Response<GetLinksResponse>, Status> {
        let r = req.into_inner();
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let links = self
            .db
            .get_links(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        Ok(Response::new(GetLinksResponse {
            links: links.iter().map(to_proto_link).collect(),
        }))
    }
    async fn get_linked_objects(
        &self,
        req: Request<GetLinkedObjectsRequest>,
    ) -> Result<Response<GetLinkedObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let objs = self
            .db
            .get_linked_objects(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        let objs = self.resolve_computed_for_responses(objs, &principals)?;
        Ok(Response::new(GetLinkedObjectsResponse {
            objects: objs.iter().map(to_proto_obj).collect(),
        }))
    }
    async fn traverse(
        &self,
        req: Request<TraverseRequest>,
    ) -> Result<Response<TraverseResponse>, Status> {
        let principals = caller_principals(&req);
        let q = req
            .into_inner()
            .query
            .ok_or(Status::invalid_argument("query required"))?;
        let gq = crate::sekai::query::GraphQuery {
            start_id: q.start_id,
            start_external_id: q.start_external_id,
            relations: q.relations,
            direction: if q.direction == "incoming" {
                domain::Direction::Incoming
            } else {
                domain::Direction::Outgoing
            },
            max_depth: q.max_depth,
            kind_filter: q.kind_filter,
            interface_filter: q.interface_filter,
            property_filter: q.property_filter,
        };
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        let queried_properties = gq.property_filter.keys().cloned().collect::<Vec<_>>();
        if gq.kind_filter.is_empty() {
            ensure_property_query_allowed(&schema, &principals, "", queried_properties)?;
        } else {
            for kind in &gq.kind_filter {
                ensure_property_query_allowed(
                    &schema,
                    &principals,
                    kind,
                    queried_properties.clone(),
                )?;
            }
        }
        let mut res = crate::sekai::query::traverse(&self.db, &gq, Some(&schema))
            .map_err(Status::internal)?;
        drop(schema);
        res.objects = self.resolve_computed_for_responses(res.objects, &principals)?;
        Ok(Response::new(TraverseResponse {
            result: Some(GraphResult {
                objects: res.objects.iter().map(to_proto_obj).collect(),
                links: res.links.iter().map(to_proto_link).collect(),
            }),
        }))
    }
    async fn list_schema_types(
        &self,
        req: Request<ListSchemaTypesRequest>,
    ) -> Result<Response<ListSchemaTypesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let types = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .all()
            .iter()
            .filter(|object_type| {
                check_read(
                    &self.security,
                    &schema_object_id(&object_type.kind),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_schema_type)
            .collect();
        Ok(Response::new(ListSchemaTypesResponse { types }))
    }
    async fn create_schema_type(
        &self,
        req: Request<CreateSchemaTypeRequest>,
    ) -> Result<Response<CreateSchemaTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let object_type = req
            .into_inner()
            .r#type
            .ok_or(Status::invalid_argument("schema type required"))?;
        let parsed = from_proto_schema_type(&object_type)?;
        check_schema_admin(&self.security, &parsed.kind, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema::validate_object_type_definition(&parsed, registry.get(&parsed.kind), &registry)
                .map_err(Status::invalid_argument)?;
        }
        validate_computed_property_functions(&self.db, &parsed)?;
        self.db
            .upsert_object_type(&parsed)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .register(parsed.clone());
        self.schema_load_errors
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&parsed.kind);
        Ok(Response::new(CreateSchemaTypeResponse {
            r#type: Some(to_proto_schema_type(&parsed)),
        }))
    }
    async fn delete_schema_type(
        &self,
        req: Request<DeleteSchemaTypeRequest>,
    ) -> Result<Response<DeleteSchemaTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let kind = req.into_inner().kind;
        if kind.trim().is_empty() {
            return Err(Status::invalid_argument("kind required"));
        }
        check_schema_admin(&self.security, &kind, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if registry
                .get(&kind)
                .map(|object_type| object_type.is_builtin)
                .unwrap_or(false)
            {
                return Err(Status::invalid_argument(
                    "cannot delete builtin schema type",
                ));
            }
        }
        self.db
            .delete_object_type(&kind)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&kind);
        self.schema_load_errors
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&kind);
        Ok(Response::new(DeleteSchemaTypeResponse {}))
    }

    async fn list_interfaces(
        &self,
        req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let interfaces = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .all_interfaces()
            .iter()
            .filter(|interface| {
                check_read(
                    &self.security,
                    &interface_object_id(&interface.name),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_interface)
            .collect();
        Ok(Response::new(ListInterfacesResponse { interfaces }))
    }

    async fn create_interface(
        &self,
        req: Request<CreateInterfaceRequest>,
    ) -> Result<Response<CreateInterfaceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let interface = req
            .into_inner()
            .interface
            .ok_or(Status::invalid_argument("interface required"))?;
        let parsed = from_proto_interface(&interface)?;
        check_interface_admin(&self.security, &parsed.name, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema::validate_interface_definition(&parsed, registry.get_interface(&parsed.name))
                .map_err(Status::invalid_argument)?;
            let mut updated_registry = registry.clone();
            updated_registry.register_interface(parsed.clone());
            for object_type in updated_registry.all() {
                if object_type
                    .implements
                    .iter()
                    .any(|interface| interface == &parsed.name)
                {
                    schema::validate_object_type_definition(
                        &object_type,
                        updated_registry.get(&object_type.kind),
                        &updated_registry,
                    )
                    .map_err(Status::invalid_argument)?;
                }
            }
        }
        self.db
            .upsert_interface(&parsed)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .register_interface(parsed.clone());
        Ok(Response::new(CreateInterfaceResponse {
            interface: Some(to_proto_interface(&parsed)),
        }))
    }

    async fn delete_interface(
        &self,
        req: Request<DeleteInterfaceRequest>,
    ) -> Result<Response<DeleteInterfaceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("interface name required"));
        }
        check_interface_admin(&self.security, &name, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if registry
                .get_interface(&name)
                .map(|interface| interface.is_builtin)
                .unwrap_or(false)
            {
                return Err(Status::invalid_argument("cannot delete builtin interface"));
            }
            if registry.all().iter().any(|object_type| {
                object_type
                    .implements
                    .iter()
                    .any(|interface| interface == &name)
            }) {
                return Err(Status::failed_precondition(
                    "cannot delete interface while schema types implement it",
                ));
            }
        }
        self.db.delete_interface(&name).map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove_interface(&name);
        Ok(Response::new(DeleteInterfaceResponse {}))
    }

    async fn create_action_type(
        &self,
        req: Request<CreateActionTypeRequest>,
    ) -> Result<Response<CreateActionTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let action_type = req
            .into_inner()
            .action_type
            .ok_or(Status::invalid_argument("action_type required"))?;
        let parsed = from_proto_action_type(&action_type)?;
        check_action_admin(&self.security, &parsed.name, &principals)?;
        {
            action::validate_action_type_definition(
                &parsed,
                ActionExecutor::new().has_action(&parsed.name),
            )
            .map_err(Status::invalid_argument)?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            validate_action_type_against_schema(&parsed, &schema)?;
        }
        let stored = self
            .db
            .upsert_action_type(&parsed)
            .map_err(Status::internal)?;
        self.actions
            .write()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .register_action_type(stored.clone())
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateActionTypeResponse {
            action_type: Some(to_proto_action_type(&stored)),
        }))
    }

    async fn list_action_types(
        &self,
        req: Request<ListActionTypesRequest>,
    ) -> Result<Response<ListActionTypesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let action_types = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .list_action_types()
            .iter()
            .filter(|action_type| {
                check_read(
                    &self.security,
                    &action_object_id(&action_type.name),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_action_type)
            .collect();
        Ok(Response::new(ListActionTypesResponse { action_types }))
    }

    async fn delete_action_type(
        &self,
        req: Request<DeleteActionTypeRequest>,
    ) -> Result<Response<DeleteActionTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("name required"));
        }
        check_action_admin(&self.security, &name, &principals)?;
        if self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .has_action(&name)
            && ActionExecutor::new().has_action(&name)
        {
            return Err(Status::invalid_argument("cannot delete builtin action"));
        }
        self.db
            .delete_action_type(&name)
            .map_err(Status::internal)?;
        self.actions
            .write()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .remove_action_type(&name);
        Ok(Response::new(DeleteActionTypeResponse {}))
    }

    async fn execute_action(
        &self,
        req: Request<ExecuteActionRequest>,
    ) -> Result<Response<ExecuteActionResponse>, Status> {
        let principals = caller_principals(&req);
        let work_unit = work_unit_from_metadata(&req);
        let inner = req.into_inner();
        let dry_run = inner.dry_run;
        let r = inner
            .request
            .ok_or(Status::invalid_argument("request required"))?;
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(&r.action);
        let sensitive_params = actions.sensitive_param_names(&r.action);
        let target_ids = actions
            .target_ids(&self.db, &r.action, &r.params)
            .map_err(|err| {
                if mask_missing_link && err == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(err)
                }
            })?;
        for target_id in &target_ids {
            check_write(&self.security, target_id, &principals)?;
        }
        let actor = principals.first().cloned().unwrap_or_default();
        // Governed-action policy gate (Plan 9, Phase A). Resolved by
        // agent-then-namespace scope; no policy == allow (backward compatible).
        let action_risk = actions.action_risk_class(&r.action);
        let policy_namespace = action_policy_namespace(&self.db, &target_ids, &r.params);
        let resolved_policy = self
            .db
            .resolve_action_policy(&actor, &policy_namespace)
            .map_err(Status::internal)?;
        let (decision, policy_scope) = match &resolved_policy {
            Some(policy) => (policy.decide(&r.action, action_risk), policy.scope.clone()),
            None => (ActionDecision::Allow, String::new()),
        };

        // Dry-run (Plan 9, Phase B): report the planned ops and the resolved
        // decision without executing or erroring, leaving the graph untouched.
        if dry_run {
            let planned_ops = actions
                .planned_ops(&r.action, &r.params)
                .map_err(Status::invalid_argument)?;
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("decision".into(), decision.as_str().into());
            evidence.insert("dry_run".into(), "true".into());
            if !policy_scope.is_empty() {
                evidence.insert("policy_scope".into(), policy_scope.clone());
            }
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: actor.clone(),
                    action: r.action.clone(),
                    reason: "execute_action_dry_run".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: format!(
                        "dry-run: {} planned op(s), decision={}",
                        planned_ops.len(),
                        decision.as_str()
                    ),
                })
                .map_err(Status::internal)?;
            return Ok(Response::new(ExecuteActionResponse {
                result: Some(ActionResult {
                    action: r.action,
                    message: format!("dry run: {} planned op(s)", planned_ops.len()),
                    dry_run: true,
                    planned_ops,
                    decision: decision.as_str().into(),
                    approval_id: String::new(),
                }),
            }));
        }

        if decision == ActionDecision::RequireApproval {
            // Phase B: hold the action for out-of-band approval instead of
            // executing. Persist the exact params so it can be resumed.
            let approval = action_approval::ActionApproval::pending(
                actor.clone(),
                r.action.clone(),
                r.params.clone(),
                work_unit.clone(),
                policy_scope.clone(),
                action_risk.as_str(),
                target_ids.first().cloned().unwrap_or_default(),
                now_millis(),
            );
            self.db
                .create_action_approval(&approval)
                .map_err(Status::internal)?;
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("policy_scope".into(), policy_scope.clone());
            evidence.insert("decision".into(), decision.as_str().into());
            evidence.insert("approval_id".into(), approval.id.clone());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: actor.clone(),
                    action: r.action.clone(),
                    reason: "action_approval_pending".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: format!("held for approval: {}", approval.id),
                })
                .map_err(Status::internal)?;
            return Ok(Response::new(ExecuteActionResponse {
                result: Some(ActionResult {
                    action: r.action,
                    message: format!("action held for approval: {}", approval.id),
                    dry_run: false,
                    planned_ops: Vec::new(),
                    decision: decision.as_str().into(),
                    approval_id: approval.id,
                }),
            }));
        }

        if decision == ActionDecision::Deny {
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("policy_scope".into(), policy_scope.clone());
            evidence.insert("decision".into(), decision.as_str().into());
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: actor.clone(),
                    action: r.action.clone(),
                    reason: "action_policy_denied".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: format!("{} by action policy {}", decision.as_str(), policy_scope),
                })
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(format!(
                "action {} denied by policy",
                r.action
            )));
        }

        // Blast-radius caps (Plan 9, Phase C): hard-stop runaway loops by
        // capping mutations/deletes per work unit. Only enforced when a policy
        // sets a cap and the call carries a work-unit attribution.
        let blast_caps = resolved_policy.as_ref().and_then(|policy| {
            match (
                policy.max_mutations_per_work_unit,
                policy.max_deletes_per_work_unit,
            ) {
                (None, None) => None,
                caps => Some(caps),
            }
        });
        let (op_mutations, op_deletes) = actions.action_op_counts(&r.action, &r.params);
        if !work_unit.is_empty()
            && let Some((max_mutations, max_deletes)) = blast_caps
        {
            let (used_mutations, used_deletes) = self
                .db
                .get_blast_radius(&work_unit)
                .map_err(Status::internal)?;
            let exceeds = |cap: Option<u32>, used: u32, add: u32| {
                cap.is_some_and(|cap| used.saturating_add(add) > cap)
            };
            if exceeds(max_deletes, used_deletes, op_deletes)
                || exceeds(max_mutations, used_mutations, op_mutations)
            {
                let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
                evidence.insert("risk_class".into(), action_risk.as_str().into());
                evidence.insert("policy_scope".into(), policy_scope.clone());
                evidence.insert("work_unit".into(), work_unit.clone());
                evidence.insert("used_mutations".into(), used_mutations.to_string());
                evidence.insert("used_deletes".into(), used_deletes.to_string());
                self.db
                    .record_decision(&audit::Decision {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "action_blast_radius_exceeded".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!("blast-radius cap exceeded for work unit {}", work_unit),
                    })
                    .map_err(Status::internal)?;
                return Err(Status::resource_exhausted(format!(
                    "blast-radius cap exceeded for work unit {}",
                    work_unit
                )));
            }
        }

        // Action-class budget (Plan 9, Phase C): meter effectful actions against
        // a chisei budget subject `action:<risk_class>`. No limit == allow.
        let budget_subject = format!("action:{}", action_risk.as_str());
        if let Some(budget) = &self.budget
            && let Err(err) = budget.check(&budget_subject, 1)
        {
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("budget_subject".into(), budget_subject.clone());
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: actor.clone(),
                    action: r.action.clone(),
                    reason: "action_budget_exceeded".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: err,
                })
                .map_err(Status::internal)?;
            return Err(Status::resource_exhausted(format!(
                "action budget exhausted for {}",
                budget_subject
            )));
        }
        let schema_kinds = actions
            .schema_kinds(&self.db, &r.action, &r.params)
            .map_err(Status::invalid_argument)?;
        for kind in schema_kinds {
            self.require_schema_kind_loaded(&kind)?;
        }
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        actions
            .validate_action_schema(&r.action, &schema)
            .map_err(Status::invalid_argument)?;
        let schema_restricted_property =
            schema_restricted_action_property(&self.db, &schema, &r.params);
        let msg = actions
            .execute(&self.db, &schema, &r.action, &r.params, &actor)
            .map_err(Status::invalid_argument)?;
        drop(actions);
        drop(schema);
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor,
                action: r.action.clone(),
                reason: "execute_action".into(),
                evidence: redact_action_evidence(
                    &r.params,
                    &sensitive_params,
                    schema_restricted_property,
                ),
                target_id: target_ids.first().cloned().unwrap_or_default(),
                outcome: redact_action_outcome(
                    &r.action,
                    &r.params,
                    &msg,
                    schema_restricted_property,
                ),
            })
            .map_err(Status::internal)?;
        // Record the effect against the work unit's blast-radius counters.
        if !work_unit.is_empty() && blast_caps.is_some() && (op_mutations > 0 || op_deletes > 0) {
            let _ = self
                .db
                .add_blast_radius(&work_unit, op_mutations, op_deletes);
        }
        // Record action-class budget usage (one unit per executed action).
        if let Some(budget) = &self.budget {
            budget.record(&budget_subject, 1);
        }
        Ok(Response::new(ExecuteActionResponse {
            result: Some(ActionResult {
                action: r.action,
                message: msg,
                dry_run: false,
                planned_ops: Vec::new(),
                decision: decision.as_str().into(),
                approval_id: String::new(),
            }),
        }))
    }
    async fn set_action_policy(
        &self,
        req: Request<SetActionPolicyRequest>,
    ) -> Result<Response<SetActionPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy = req
            .into_inner()
            .policy
            .ok_or(Status::invalid_argument("policy required"))?;
        let domain_policy = from_proto_action_policy(&policy)?;
        check_action_admin(&self.security, &domain_policy.scope, &principals)?;
        self.db
            .upsert_action_policy(&domain_policy)
            .map_err(Status::internal)?;
        Ok(Response::new(SetActionPolicyResponse {
            policy: Some(to_proto_action_policy(&domain_policy)),
        }))
    }

    async fn get_action_policy(
        &self,
        req: Request<GetActionPolicyRequest>,
    ) -> Result<Response<GetActionPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        check_action_admin(&self.security, &r.scope, &principals)?;
        let policy = self
            .db
            .get_action_policy(&r.scope)
            .map_err(Status::internal)?;
        Ok(Response::new(GetActionPolicyResponse {
            policy: policy.map(|policy| to_proto_action_policy(&policy)),
        }))
    }

    async fn list_action_policies(
        &self,
        req: Request<ListActionPoliciesRequest>,
    ) -> Result<Response<ListActionPoliciesResponse>, Status> {
        let principals = caller_principals(&req);
        check_action_admin(&self.security, "", &principals)?;
        let policies = self.db.list_action_policies().map_err(Status::internal)?;
        Ok(Response::new(ListActionPoliciesResponse {
            policies: policies.iter().map(to_proto_action_policy).collect(),
        }))
    }

    async fn approve_action(
        &self,
        req: Request<ApproveActionRequest>,
    ) -> Result<Response<ApproveActionResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let mut approval = self
            .db
            .get_action_approval(&r.approval_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("approval not found"))?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        if approval.status != action_approval::ApprovalStatus::Pending {
            return Err(Status::failed_precondition(format!(
                "approval {} is already {}",
                approval.id,
                approval.status.as_str()
            )));
        }
        let approver = principals.first().cloned().unwrap_or_default();

        // Re-check policy at execution time: a tightened policy that now denies
        // the action must block the resume even though it was approved.
        let target_ids = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions
                .target_ids(&self.db, &approval.action, &approval.params)
                .unwrap_or_default()
        };
        let namespace = action_policy_namespace(&self.db, &target_ids, &approval.params);
        let action_risk = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions.action_risk_class(&approval.action)
        };
        if let Some(policy) = self
            .db
            .resolve_action_policy(&approval.actor, &namespace)
            .map_err(Status::internal)?
            && policy.decide(&approval.action, action_risk) == ActionDecision::Deny
        {
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: approver,
                    action: approval.action.clone(),
                    reason: "action_approval_policy_denied".into(),
                    evidence: HashMap::from([
                        ("approval_id".into(), approval.id.clone()),
                        ("policy_scope".into(), policy.scope.clone()),
                    ]),
                    target_id: approval.target_id.clone(),
                    outcome: "policy now denies the held action".into(),
                })
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "action policy now denies this approval",
            ));
        }

        // Resume the effect, re-checking write access for the original proposer.
        let proposer = vec![approval.actor.clone()];
        let msg = self.run_action_effect(
            &approval.action,
            &approval.params,
            &approval.actor,
            &proposer,
        )?;

        approval.status = action_approval::ApprovalStatus::Approved;
        approval.decided_by = principals.first().cloned().unwrap_or_default();
        approval.outcome = msg.clone();
        approval.updated = now_millis();
        self.db
            .update_action_approval(&approval)
            .map_err(Status::internal)?;
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor: approval.decided_by.clone(),
                action: approval.action.clone(),
                reason: "action_approval_approved".into(),
                evidence: HashMap::from([("approval_id".into(), approval.id.clone())]),
                target_id: approval.target_id.clone(),
                outcome: msg.clone(),
            })
            .map_err(Status::internal)?;

        Ok(Response::new(ApproveActionResponse {
            result: Some(ActionResult {
                action: approval.action.clone(),
                message: msg,
                dry_run: false,
                planned_ops: Vec::new(),
                decision: "approved".into(),
                approval_id: approval.id.clone(),
            }),
            approval: Some(to_proto_action_approval(&approval)),
        }))
    }

    async fn deny_action(
        &self,
        req: Request<DenyActionRequest>,
    ) -> Result<Response<DenyActionResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let mut approval = self
            .db
            .get_action_approval(&r.approval_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("approval not found"))?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        if approval.status != action_approval::ApprovalStatus::Pending {
            return Err(Status::failed_precondition(format!(
                "approval {} is already {}",
                approval.id,
                approval.status.as_str()
            )));
        }
        approval.status = action_approval::ApprovalStatus::Denied;
        approval.decided_by = principals.first().cloned().unwrap_or_default();
        approval.outcome = if r.reason.trim().is_empty() {
            "denied".to_string()
        } else {
            r.reason.trim().to_string()
        };
        approval.updated = now_millis();
        self.db
            .update_action_approval(&approval)
            .map_err(Status::internal)?;
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor: approval.decided_by.clone(),
                action: approval.action.clone(),
                reason: "action_approval_denied".into(),
                evidence: HashMap::from([("approval_id".into(), approval.id.clone())]),
                target_id: approval.target_id.clone(),
                outcome: approval.outcome.clone(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(DenyActionResponse {
            approval: Some(to_proto_action_approval(&approval)),
        }))
    }

    async fn list_pending_approvals(
        &self,
        req: Request<ListPendingApprovalsRequest>,
    ) -> Result<Response<ListPendingApprovalsResponse>, Status> {
        let principals = caller_principals(&req);
        check_action_admin(&self.security, "", &principals)?;
        let r = req.into_inner();
        let status = match r.status.trim().to_ascii_lowercase().as_str() {
            "" | "pending" => Some(action_approval::ApprovalStatus::Pending),
            "all" => None,
            other => Some(
                action_approval::ApprovalStatus::parse(other)
                    .ok_or_else(|| Status::invalid_argument("invalid status filter"))?,
            ),
        };
        let approvals = self
            .db
            .list_action_approvals(status)
            .map_err(Status::internal)?;
        Ok(Response::new(ListPendingApprovalsResponse {
            approvals: approvals.iter().map(to_proto_action_approval).collect(),
        }))
    }

    async fn get_lineage(
        &self,
        req: Request<GetLineageRequest>,
    ) -> Result<Response<GetLineageResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let res = crate::sekai::lineage::get_lineage(&self.db, &r.object_id, r.max_nodes as usize)
            .map_err(Status::internal)?;
        let objects = self.resolve_computed_for_responses(
            res.nodes.iter().map(|node| node.object.clone()).collect(),
            &principals,
        )?;
        let nodes = res
            .nodes
            .iter()
            .zip(objects.iter())
            .map(|(n, object)| LineageNode {
                object: Some(to_proto_obj(object)),
                role: n.role.clone(),
                ephemeral: n.ephemeral,
            })
            .collect();
        let edges = res
            .edges
            .iter()
            .map(|e| LineageEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                relation: e.relation.clone(),
            })
            .collect();
        Ok(Response::new(GetLineageResponse {
            result: Some(LineageResult {
                nodes,
                edges,
                truncated: res.truncated,
            }),
        }))
    }
    async fn create_contention_scope(
        &self,
        req: Request<CreateContentionScopeRequest>,
    ) -> Result<Response<CreateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let mut scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_contention_scope")
            .map_err(Status::internal)?
            .filter(|record| record.principal == owner)
        {
            let scope = self
                .db
                .get_contention_scope(&existing.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            return Ok(Response::new(CreateContentionScopeResponse {
                scope: Some(to_proto_contention_scope(&scope)),
            }));
        }
        if scope.owner_principal.is_empty() {
            scope.owner_principal = owner;
        }
        self.db
            .create_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn update_contention_scope(
        &self,
        req: Request<UpdateContentionScopeRequest>,
    ) -> Result<Response<UpdateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let existing = self
            .db
            .get_contention_scope(&scope.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_write(&existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "update_contention_scope")
            .map_err(Status::internal)?
        {
            if record.scope_id == scope.id && record.principal == dedup_principal(&principals) {
                let scope = self
                    .db
                    .get_contention_scope(&scope.id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("scope not found"))?;
                return Ok(Response::new(UpdateContentionScopeResponse {
                    scope: Some(to_proto_contention_scope(&scope)),
                }));
            }
        }
        self.db
            .update_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "update_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(UpdateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn get_contention_scope(
        &self,
        req: Request<GetContentionScopeRequest>,
    ) -> Result<Response<GetContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scope = self
            .db
            .get_contention_scope(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        Ok(Response::new(GetContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn list_contention_scopes(
        &self,
        req: Request<ListContentionScopesRequest>,
    ) -> Result<Response<ListContentionScopesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|scope| check_scope_read(scope, &principals).is_ok())
            .map(|scope| to_proto_contention_scope(&scope))
            .collect();
        Ok(Response::new(ListContentionScopesResponse { scopes }))
    }
    async fn create_work_unit(
        &self,
        req: Request<CreateWorkUnitRequest>,
    ) -> Result<Response<CreateWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let mut work_unit = inner
            .work_unit
            .ok_or(Status::invalid_argument("work_unit required"))
            .map(|work_unit| from_proto_work_unit(&work_unit))?;
        let principal = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_work_unit")
            .map_err(Status::internal)?
            .filter(|record| record.principal == principal)
        {
            let work_unit = self
                .db
                .get_work_unit(&existing.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            return Ok(Response::new(CreateWorkUnitResponse {
                work_unit: Some(to_proto_work_unit(&work_unit)),
            }));
        }
        if !work_unit.idempotency_key.is_empty() {
            if let Some(existing) = self
                .db
                .get_work_unit_by_idempotency_key(&work_unit.idempotency_key)
                .map_err(Status::internal)?
            {
                check_work_unit_read(&self.security, &existing, &principals)?;
                return Ok(Response::new(CreateWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&existing)),
                }));
            }
        }
        if !work_unit.target_object_id.is_empty() {
            check_write(&self.security, &work_unit.target_object_id, &principals)?;
        }
        let scope = self
            .db
            .get_contention_scope(&work_unit.scope_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        initialize_work_unit_for_create(&mut work_unit, &principal);
        self.db
            .create_work_unit(&work_unit)
            .map_err(Status::invalid_argument)?;
        let event = coordination::RunEvent {
            id: format!("evt:{}:created:{}", work_unit.id, work_unit.created_at),
            work_unit_id: work_unit.id.clone(),
            event_type: "created".into(),
            message: "work unit created".into(),
            evidence: std::collections::HashMap::from([(
                "scope_id".into(),
                work_unit.scope_id.clone(),
            )]),
            created_at: work_unit.created_at,
        };
        self.db.append_run_event(&event).map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn get_work_unit(
        &self,
        req: Request<GetWorkUnitRequest>,
    ) -> Result<Response<GetWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let work_unit = self
            .db
            .get_work_unit(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.security, &work_unit, &principals)?;
        Ok(Response::new(GetWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn list_work_units(
        &self,
        req: Request<ListWorkUnitsRequest>,
    ) -> Result<Response<ListWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let filter = req.into_inner().filter.unwrap_or_default();
        let limit = filter.limit;
        let mut work_units = self
            .db
            .list_work_units(&from_proto_work_unit_filter(&filter))
            .map_err(Status::internal)?
            .into_iter()
            .filter(|work_unit| {
                check_work_unit_read(&self.security, work_unit, &principals).is_ok()
            })
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && work_units.len() > limit as usize {
            let next = work_units
                .get((limit as usize).saturating_sub(1))
                .map(|work_unit| coordination::make_page_token(work_unit.created_at, &work_unit.id))
                .unwrap_or_default();
            trim_page(&mut work_units, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListWorkUnitsResponse {
            work_units: work_units.iter().map(to_proto_work_unit).collect(),
            next_page_token,
        }))
    }
    async fn try_admit_work_unit(
        &self,
        req: Request<TryAdmitWorkUnitRequest>,
    ) -> Result<Response<TryAdmitWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let work_unit = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &work_unit, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "try_admit_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id
                && record.principal == dedup_principal(&principals)
            {
                let current = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                let reservations = self
                    .db
                    .list_reservations(&coordination::ReservationFilter {
                        work_unit_id: Some(work_unit_id.clone()),
                        status: Some(coordination::RESERVATION_STATUS_ACTIVE.into()),
                        ..Default::default()
                    })
                    .map_err(Status::internal)?;
                return Ok(Response::new(TryAdmitWorkUnitResponse {
                    admitted: current.status == coordination::WORK_UNIT_STATUS_RUNNING,
                    queue_position: 0,
                    reason: String::new(),
                    work_unit: Some(to_proto_work_unit(&current)),
                    reservations: reservations.iter().map(to_proto_reservation).collect(),
                }));
            }
        }
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        let result = self
            .db
            .try_admit_work_unit(&work_unit_id, &owner, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "try_admit_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: result.work_unit.scope_id.clone(),
                work_unit_id: result.work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(TryAdmitWorkUnitResponse {
            admitted: result.admitted,
            queue_position: result.queue_position,
            reason: result.reason,
            work_unit: Some(to_proto_work_unit(&result.work_unit)),
            reservations: result
                .reservations
                .iter()
                .map(to_proto_reservation)
                .collect(),
        }))
    }
    async fn heartbeat_work_unit(
        &self,
        req: Request<HeartbeatWorkUnitRequest>,
    ) -> Result<Response<HeartbeatWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "heartbeat_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(HeartbeatWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .heartbeat_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "heartbeat_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(HeartbeatWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn complete_work_unit(
        &self,
        req: Request<CompleteWorkUnitRequest>,
    ) -> Result<Response<CompleteWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "complete_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CompleteWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .complete_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "complete_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CompleteWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn fail_work_unit(
        &self,
        req: Request<FailWorkUnitRequest>,
    ) -> Result<Response<FailWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "fail_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(FailWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .fail_work_unit(
                &inner.work_unit_id,
                &inner.failure_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "fail_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(FailWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn cancel_work_unit(
        &self,
        req: Request<CancelWorkUnitRequest>,
    ) -> Result<Response<CancelWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "cancel_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CancelWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .cancel_work_unit(
                &inner.work_unit_id,
                &inner.cancel_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "cancel_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CancelWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn release_reservation(
        &self,
        req: Request<ReleaseReservationRequest>,
    ) -> Result<Response<ReleaseReservationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "release_reservation")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                return Ok(Response::new(ReleaseReservationResponse { released: 0 }));
            }
        }
        let released = self
            .db
            .release_reservations_for_work_unit(
                &work_unit_id,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "release_reservation".into(),
                principal: dedup_principal(&principals),
                scope_id: existing.scope_id.clone(),
                work_unit_id: existing.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(ReleaseReservationResponse { released }))
    }
    async fn list_reservations(
        &self,
        req: Request<ListReservationsRequest>,
    ) -> Result<Response<ListReservationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let reservations = self
            .db
            .list_reservations(&coordination::ReservationFilter {
                work_unit_id: if inner.work_unit_id.is_empty() {
                    None
                } else {
                    Some(inner.work_unit_id)
                },
                scope_id: if inner.scope_id.is_empty() {
                    None
                } else {
                    Some(inner.scope_id)
                },
                status: if inner.status.is_empty() {
                    None
                } else {
                    Some(inner.status)
                },
            })
            .map_err(Status::internal)?;
        let mut visible = Vec::new();
        for reservation in reservations {
            if let Some(work_unit) = self
                .db
                .get_work_unit(&reservation.work_unit_id)
                .map_err(Status::internal)?
            {
                if check_work_unit_read(&self.security, &work_unit, &principals).is_ok() {
                    visible.push(to_proto_reservation(&reservation));
                }
            }
        }
        Ok(Response::new(ListReservationsResponse {
            reservations: visible,
        }))
    }
    async fn list_run_events(
        &self,
        req: Request<ListRunEventsRequest>,
    ) -> Result<Response<ListRunEventsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.security, &work_unit, &principals)?;
        let limit = inner.limit;
        let mut events = self
            .db
            .list_run_events(
                &inner.work_unit_id,
                inner.limit,
                inner.after,
                &inner.event_types,
                if inner.page_token.is_empty() {
                    None
                } else {
                    Some(inner.page_token.as_str())
                },
            )
            .map_err(Status::internal)?
            .into_iter()
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && events.len() > limit as usize {
            let next = events
                .get((limit as usize).saturating_sub(1))
                .map(|event| coordination::make_page_token(event.created_at, &event.id))
                .unwrap_or_default();
            trim_page(&mut events, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListRunEventsResponse {
            events: events.iter().map(to_proto_run_event).collect(),
            next_page_token,
        }))
    }
    async fn reconcile_work_units(
        &self,
        req: Request<ReconcileWorkUnitsRequest>,
    ) -> Result<Response<ReconcileWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let summary = if !inner.work_unit_id.is_empty() {
            let work_unit = self
                .db
                .get_work_unit(&inner.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            let scope = self
                .db
                .get_contention_scope(&work_unit.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            if !inner.scope_id.is_empty() && inner.scope_id != work_unit.scope_id {
                return Ok(Response::new(ReconcileWorkUnitsResponse {
                    work_units_reconciled: 0,
                    reservations_released: 0,
                    details: Vec::new(),
                }));
            }
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: Some(inner.work_unit_id),
                        scope_id: if inner.scope_id.is_empty() {
                            None
                        } else {
                            Some(inner.scope_id)
                        },
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else if !inner.scope_id.is_empty() {
            let scope = self
                .db
                .get_contention_scope(&inner.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: None,
                        scope_id: Some(inner.scope_id),
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else {
            let mut owned_scope_ids: Vec<String> = self
                .db
                .list_contention_scopes()
                .map_err(Status::internal)?
                .into_iter()
                .filter(|scope| principal_matches(&scope.owner_principal, &principals))
                .map(|scope| scope.id)
                .collect();
            owned_scope_ids.sort();
            if owned_scope_ids.is_empty() {
                return Err(Status::permission_denied(
                    "reconcile requires scope ownership",
                ));
            }
            let mut summary = coordination::ReconcileSummary::default();
            for scope_id in owned_scope_ids {
                reconcile_owned_scope(
                    &self.db,
                    now_ms,
                    scope_id,
                    inner.dry_run,
                    inner.limit,
                    &mut summary,
                )?;
            }
            summary
        };
        Ok(Response::new(ReconcileWorkUnitsResponse {
            work_units_reconciled: summary.work_units_reconciled,
            reservations_released: summary.reservations_released,
            details: summary
                .details
                .iter()
                .map(|detail| ReconciliationDetail {
                    work_unit_id: detail.work_unit_id.clone(),
                    reservation_id: detail.reservation_id.clone(),
                    reason: detail.reason.clone(),
                    action: detail.action.clone(),
                })
                .collect(),
        }))
    }
    async fn get_coordination_snapshot(
        &self,
        req: Request<GetCoordinationSnapshotRequest>,
    ) -> Result<Response<GetCoordinationSnapshotResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let visible_scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .any(|scope| principal_matches(&scope.owner_principal, &principals));
        if !visible_scopes {
            return Err(Status::permission_denied(
                "snapshot requires scope ownership",
            ));
        }
        let snapshot = self
            .db
            .coordination_snapshot(chrono::Utc::now().timestamp_millis())
            .map_err(Status::internal)?;
        Ok(Response::new(GetCoordinationSnapshotResponse {
            snapshot: Some(to_proto_snapshot(&snapshot)),
        }))
    }
    // --- Remaining RPCs return unimplemented for now (wired in detail later) ---
    async fn create_function(
        &self,
        req: Request<CreateFunctionRequest>,
    ) -> Result<Response<CreateFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let function = req
            .into_inner()
            .function
            .ok_or(Status::invalid_argument("function required"))?;
        let parsed = from_proto_function(&function);
        self.db
            .create_function(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateFunctionResponse {
            function: Some(to_proto_function(&parsed)),
        }))
    }
    async fn list_functions(
        &self,
        req: Request<ListFunctionsRequest>,
    ) -> Result<Response<ListFunctionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let functions = self
            .db
            .list_functions()
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_function)
            .collect();
        Ok(Response::new(ListFunctionsResponse { functions }))
    }
    async fn execute_function(
        &self,
        req: Request<ExecuteFunctionRequest>,
    ) -> Result<Response<ExecuteFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let function = self
            .db
            .get_function(&inner.name)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("function not found"))?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_function_allows_restricted_properties(&schema, &principals, &function)?;
        }
        let result = function::execute_with_filter(&self.db, &function, &inner.params, |object| {
            self.security.can_access(&object.id, &refs)
        })
        .map_err(Status::invalid_argument)?;
        let objects = self.resolve_computed_for_responses(result.objects, &principals)?;
        Ok(Response::new(ExecuteFunctionResponse {
            result: Some(FunctionResult {
                objects: objects.iter().map(to_proto_obj).collect(),
                aggregates: result.aggregates,
            }),
        }))
    }
    async fn create_dataset(
        &self,
        req: Request<CreateDatasetRequest>,
    ) -> Result<Response<CreateDatasetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let dataset = req
            .into_inner()
            .dataset
            .ok_or(Status::invalid_argument("dataset required"))?;
        let parsed = from_proto_dataset(&dataset);
        if !parsed.object_id.is_empty() {
            check_write(&self.security, &parsed.object_id, &principals)?;
        }
        self.db
            .create_dataset(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateDatasetResponse {
            dataset: Some(to_proto_dataset(&parsed)),
        }))
    }
    async fn list_datasets(
        &self,
        req: Request<ListDatasetsRequest>,
    ) -> Result<Response<ListDatasetsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let datasets = self
            .db
            .list_datasets()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|dataset| {
                dataset.object_id.is_empty()
                    || check_read(&self.security, &dataset.object_id, &principals).is_ok()
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_dataset)
            .collect();
        Ok(Response::new(ListDatasetsResponse { datasets }))
    }
    async fn append_rows(
        &self,
        req: Request<AppendRowsRequest>,
    ) -> Result<Response<AppendRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_write(&self.security, &dataset.object_id, &principals)?;
        }
        let rows: Vec<_> = inner.rows.into_iter().map(|r| r.values).collect();
        let count = self
            .db
            .append_rows(&inner.dataset_id, &rows)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(AppendRowsResponse { count }))
    }
    async fn query_rows(
        &self,
        req: Request<QueryRowsRequest>,
    ) -> Result<Response<QueryRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_read(&self.security, &dataset.object_id, &principals)?;
        }
        let query = inner.query.unwrap_or_default();
        let rows = self
            .db
            .query_rows(
                &inner.dataset_id,
                &dataset::RowQuery {
                    filters: from_proto_row_filters(&query.filters),
                    columns: query.columns,
                    limit: query.limit,
                    offset: query.offset,
                },
            )
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(QueryRowsResponse {
            rows: rows.into_iter().map(|values| Row { values }).collect(),
        }))
    }
    async fn create_virtual_table(
        &self,
        req: Request<CreateVirtualTableRequest>,
    ) -> Result<Response<CreateVirtualTableResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let table = req
            .into_inner()
            .table
            .ok_or(Status::invalid_argument("table required"))?;
        let parsed = from_proto_virtual_table(&table);
        let dataset = self
            .db
            .get_dataset(&parsed.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_write(&self.security, &dataset.object_id, &principals)?;
        }
        self.db
            .create_virtual_table(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateVirtualTableResponse {
            table: Some(to_proto_virtual_table(&parsed)),
        }))
    }
    async fn list_virtual_tables(
        &self,
        req: Request<ListVirtualTablesRequest>,
    ) -> Result<Response<ListVirtualTablesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tables = self
            .db
            .list_virtual_tables()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|table| {
                self.db
                    .get_dataset(&table.dataset_id)
                    .ok()
                    .flatten()
                    .map(|dataset| {
                        dataset.object_id.is_empty()
                            || check_read(&self.security, &dataset.object_id, &principals).is_ok()
                    })
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_virtual_table)
            .collect();
        Ok(Response::new(ListVirtualTablesResponse { tables }))
    }
    async fn create_grant(
        &self,
        req: Request<CreateGrantRequest>,
    ) -> Result<Response<CreateGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let grant = req
            .into_inner()
            .grant
            .ok_or(Status::invalid_argument("grant required"))?;
        let parsed = from_proto_grant(&grant)?;
        check_write(&self.security, &parsed.object_id, &principals)?;
        self.db
            .create_grant(&parsed)
            .map_err(Status::invalid_argument)?;
        self.security.add_grant(&parsed);
        Ok(Response::new(CreateGrantResponse {
            grant: Some(to_proto_grant(&parsed)),
        }))
    }
    async fn delete_grant(
        &self,
        req: Request<DeleteGrantRequest>,
    ) -> Result<Response<DeleteGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        let existing = self
            .db
            .get_grant(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("grant not found"))?;
        check_write(&self.security, &existing.object_id, &principals)?;
        let deleted = self.db.delete_grant(&id).map_err(Status::internal)?;
        if let Some(grant) = deleted {
            self.security
                .remove_grant(&grant.object_id, &grant.principal);
        }
        Ok(Response::new(DeleteGrantResponse {}))
    }
    async fn list_grants(
        &self,
        req: Request<ListGrantsRequest>,
    ) -> Result<Response<ListGrantsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let object_id = req.into_inner().object_id;
        check_write(&self.security, &object_id, &principals)?;
        let grants = self
            .db
            .list_grants(&object_id)
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_grant)
            .collect();
        Ok(Response::new(ListGrantsResponse { grants }))
    }
    async fn check_access(
        &self,
        req: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_read(&self.security, &inner.object_id, &principals)?;
        let refs: Vec<&str> = inner.principals.iter().map(String::as_str).collect();
        Ok(Response::new(CheckAccessResponse {
            allowed: self.security.can_access(&inner.object_id, &refs),
        }))
    }
    async fn record_decision(
        &self,
        req: Request<RecordDecisionRequest>,
    ) -> Result<Response<RecordDecisionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let mut decision = req
            .into_inner()
            .decision
            .ok_or_else(|| Status::invalid_argument("decision required"))?;
        if decision.id.is_empty() {
            decision.id = uuid::Uuid::new_v4().to_string();
        }
        if decision.timestamp <= 0 {
            decision.timestamp = now_millis();
        }
        self.db
            .record_decision(&audit::Decision {
                id: decision.id.clone(),
                timestamp: decision.timestamp,
                actor: decision.actor.clone(),
                action: decision.action.clone(),
                reason: decision.reason.clone(),
                evidence: decision.evidence.clone(),
                target_id: decision.target_id.clone(),
                outcome: decision.outcome.clone(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(RecordDecisionResponse {
            decision: Some(decision),
        }))
    }
    async fn list_decisions(
        &self,
        req: Request<ListDecisionsRequest>,
    ) -> Result<Response<ListDecisionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let visible_limit = if inner.limit > 0 {
            inner.limit as usize
        } else {
            100
        };
        let batch_size = visible_limit.max(50).min(200);
        let max_scan = visible_limit.saturating_mul(10).max(200);
        let actor_filter = if inner.actor.is_empty() {
            None
        } else {
            Some(inner.actor.clone())
        };
        let action_filter = if inner.action.is_empty() {
            None
        } else {
            Some(inner.action.clone())
        };
        let mut decisions = Vec::new();
        let mut offset = 0;
        let mut scanned = 0usize;
        while decisions.len() < visible_limit && scanned < max_scan {
            let batch = self
                .db
                .list_decisions(&audit::DecisionFilter {
                    actor: actor_filter.clone(),
                    action: action_filter.clone(),
                    after: inner.after,
                    limit: batch_size as i32,
                    offset,
                })
                .map_err(Status::internal)?;
            if batch.is_empty() {
                break;
            }
            scanned += batch.len();
            offset += batch.len() as i32;
            for decision in batch {
                if decision.target_id.is_empty()
                    || check_read(&self.security, &decision.target_id, &principals).is_err()
                {
                    continue;
                }
                decisions.push(Decision {
                    id: decision.id,
                    timestamp: decision.timestamp,
                    actor: decision.actor,
                    action: decision.action,
                    reason: decision.reason,
                    evidence: decision.evidence,
                    target_id: decision.target_id,
                    outcome: decision.outcome,
                });
                if decisions.len() >= visible_limit {
                    break;
                }
            }
        }
        if decisions.len() < visible_limit && scanned >= max_scan {
            return Err(Status::resource_exhausted(
                "decision visibility scan limit exceeded; refine filters",
            ));
        }
        Ok(Response::new(ListDecisionsResponse { decisions }))
    }
    async fn list_object_changes(
        &self,
        req: Request<ListObjectChangesRequest>,
    ) -> Result<Response<ListObjectChangesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_read(&self.security, &inner.object_id, &principals)?;
        let object = self
            .db
            .get_object(&inner.object_id)
            .map_err(Status::internal)?;
        let object_kind = match object.as_ref() {
            Some(object) => Some(object.kind.clone()),
            None => self
                .db
                .object_change_kind(&inner.object_id)
                .map_err(Status::internal)?,
        };
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        let changes = self
            .db
            .list_object_changes(&inner.object_id, inner.limit, inner.offset)
            .map_err(Status::internal)?
            .into_iter()
            .map(|change| {
                if let Some(kind) = object_kind.as_deref() {
                    redact_object_change_values(
                        change,
                        &inner.object_id,
                        kind,
                        &schema,
                        &self.security,
                        &principals,
                    )
                } else {
                    ObjectChange {
                        id: change.id,
                        object_id: change.object_id,
                        field: change.field,
                        old_value: change.old_value,
                        new_value: change.new_value,
                        changed_by: change.changed_by,
                        timestamp: change.timestamp,
                    }
                }
            })
            .collect();
        Ok(Response::new(ListObjectChangesResponse { changes }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        SekaiServiceImpl::new(db)
    }

    fn with_principal<T>(payload: T) -> Request<T> {
        with_named_principal(payload, "tester")
    }

    fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn widget_schema_type() -> ObjectType {
        ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            properties: vec![
                PropertyDef {
                    name: "name".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                },
                PropertyDef {
                    name: "color".into(),
                    r#type: "enum".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec!["red".into(), "blue".into()],
                    link_kind: "".into(),
                    compute_expr: "".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                },
            ],
            is_builtin: false,
            implements: vec![],
        }
    }

    fn widget_object(id: &str, properties: HashMap<String, String>) -> Object {
        Object {
            id: id.into(),
            kind: "widget".into(),
            name: "widget".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties,
            created: 0,
            updated: 0,
        }
    }

    fn grant_schema_admin(svc: &SekaiServiceImpl) {
        let grant = security::Grant {
            id: format!("schema-admin-{}", uuid::Uuid::new_v4().simple()),
            object_id: "schema".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn grant_action_admin(svc: &SekaiServiceImpl) {
        let grant = security::Grant {
            id: format!("action-admin-{}", uuid::Uuid::new_v4().simple()),
            object_id: "action".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn assign_color_action() -> ActionTypeDef {
        ActionTypeDef {
            name: "assign_color".into(),
            description: "Assign a widget color".into(),
            params: vec![ActionParamDef {
                name: "color".into(),
                r#type: "enum".into(),
                required: true,
                enum_values: vec!["red".into(), "blue".into()],
            }],
            ops: vec![ActionOp {
                op: "set_property".into(),
                property: "color".into(),
                value_from: "color".into(),
                relation: "".into(),
            }],
            target_kind: "widget".into(),
            created: 0,
        }
    }

    fn grant_object_role(
        svc: &SekaiServiceImpl,
        object_id: &str,
        principal: &str,
        role: security::Role,
    ) {
        let grant = security::Grant {
            id: format!("grant-{}", uuid::Uuid::new_v4().simple()),
            object_id: object_id.into(),
            principal: principal.into(),
            role,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn seed_domain_object(svc: &SekaiServiceImpl, id: &str) {
        svc.db
            .create_object(&domain::Object {
                id: id.into(),
                kind: "namespace".into(),
                name: id.into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn execute_action_denies_ungranted_principal_even_when_actor_claims_owner() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "set_property".into(),
                        params: HashMap::from([
                            ("id".into(), "obj-1".into()),
                            ("key".into(), "status".into()),
                            ("value".into(), "done".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "bob",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn execute_action_allows_granted_principal() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: "bob".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_records_decision_with_authenticated_actor() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "password".into()),
                        ("value".into(), "secret-value".into()),
                    ]),
                    actor: "mallory".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "alice");
        assert_eq!(decisions[0].target_id, "obj-1");
        assert_eq!(decisions[0].reason, "execute_action");
        assert_eq!(decisions[0].evidence["key"], "[redacted]");
        assert_eq!(decisions[0].evidence["value"], "[redacted]");
        assert_eq!(decisions[0].outcome, "set obj-1.password = [redacted]");
    }

    #[tokio::test]
    async fn execute_action_set_property_respects_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "set_property".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("key".into(), "color".into()),
                            ("value".into(), "green".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not in"));
        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "red");
        assert!(
            svc.db
                .list_decisions(&audit::DecisionFilter {
                    action: Some("set_property".into()),
                    ..Default::default()
                })
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execute_action_create_object_accepts_schema_properties() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "create_object".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("kind".into(), "widget".into()),
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["name"], "spinner");
        assert_eq!(obj.properties["color"], "blue");
    }

    #[tokio::test]
    async fn struct_property_round_trips_through_create_update_and_list() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "ai_result".into(),
            r#type: "struct".into(),
            required: false,
            description: "AI generated compound value".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![
                StructFieldDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                },
                StructFieldDef {
                    name: "confidence".into(),
                    r#type: "float".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                },
                StructFieldDef {
                    name: "generated_at".into(),
                    r#type: "timestamp".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                },
            ],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();

        let initial_value =
            r#"{"value":"approve","confidence":0.91,"source_objects":["widget:1"]}"#;
        let created = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("ai_result".into(), initial_value.into()),
                    ]),
                )),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(created.properties["ai_result"], initial_value);

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["ai_result"], initial_value);

        let updated_value =
            r#"{"value":"reject","confidence":0.12,"generated_at":"2026-07-06T12:00:00Z"}"#;
        let mut updated = created;
        updated
            .properties
            .insert("ai_result".into(), updated_value.into());
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(updated),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-ai").unwrap().unwrap();
        assert_eq!(stored.properties["ai_result"], updated_value);

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai-invalid",
                    HashMap::from([
                        ("name".into(), "bad".into()),
                        ("color".into(), "blue".into()),
                        ("ai_result".into(), r#"{"value":"approve"}"#.into()),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("confidence"));

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai-type-mismatch",
                    HashMap::from([
                        ("name".into(), "bad".into()),
                        ("color".into(), "blue".into()),
                        (
                            "ai_result".into(),
                            r#"{"value":"approve","confidence":"high"}"#.into(),
                        ),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("expected float"));
    }

    #[tokio::test]
    async fn object_responses_redact_restricted_schema_properties() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "secret_note".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "sensitive".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        let create_err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-denied",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("secret_note".into(), "launch code".into()),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(create_err.code(), tonic::Code::PermissionDenied);

        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(widget_object(
                    "widget-secret",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("secret_note".into(), "launch code".into()),
                    ]),
                )),
            },
            "root",
        ))
        .await
        .unwrap();

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "widget-secret".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(got.properties["name"], "spinner");
        assert_eq!(got.properties["secret_note"], "[redacted]");

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "list_widgets".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![PipelineStep {
                    op: "filter".into(),
                    kind: "widget".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                }],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let function_result = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "list_widgets".into(),
                params: HashMap::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(
            function_result.objects[0].properties["secret_note"],
            "[redacted]"
        );

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "filter_secret_widgets".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![PipelineStep {
                    op: "filter".into(),
                    kind: "widget".into(),
                    property: "secret_note".into(),
                    value: "launch code".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                }],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let function_err = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "filter_secret_widgets".into(),
                params: HashMap::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(function_err.code(), tonic::Code::PermissionDenied);

        let lineage = svc
            .get_lineage(with_principal(GetLineageRequest {
                object_id: "widget-secret".into(),
                max_nodes: 10,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(
            lineage.nodes[0].object.as_ref().unwrap().properties["secret_note"],
            "[redacted]"
        );

        let find_err = svc
            .find_by_property(with_principal(FindByPropertyRequest {
                kind: "widget".into(),
                key: "secret_note".into(),
                value: "launch code".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(find_err.code(), tonic::Code::PermissionDenied);

        let list_err = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    property_filters: vec![PropertyFilter {
                        key: "secret_note".into(),
                        op: "eq".into(),
                        value: "launch code".into(),
                    }],
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(list_err.code(), tonic::Code::PermissionDenied);

        let object_set_err = svc
            .create_object_set(with_principal(CreateObjectSetRequest {
                object_set: Some(ObjectSet {
                    id: "secret-set".into(),
                    name: "secret set".into(),
                    description: String::new(),
                    filter: Some(ListFilter {
                        kind: "widget".into(),
                        property_filters: vec![PropertyFilter {
                            key: "secret_note".into(),
                            op: "eq".into(),
                            value: "launch code".into(),
                        }],
                        limit: 10,
                        ..Default::default()
                    }),
                    owner_principal: String::new(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(object_set_err.code(), tonic::Code::PermissionDenied);

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["secret_note"], "[redacted]");

        let mut update = got;
        update.name = "renamed".into();
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(update),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-secret").unwrap().unwrap();
        assert_eq!(stored.name, "renamed");
        assert_eq!(stored.properties["secret_note"], "launch code");

        let mut attempted_overwrite = stored.clone();
        attempted_overwrite
            .properties
            .insert("secret_note".into(), "attacker code".into());
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(to_proto_obj(&attempted_overwrite)),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-secret").unwrap().unwrap();
        assert_eq!(stored.properties["secret_note"], "launch code");

        let mut changed_secret = stored.clone();
        changed_secret
            .properties
            .insert("secret_note".into(), "rotated code".into());
        svc.db
            .update_object_with_audit(&changed_secret, "root")
            .unwrap();
        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "widget-secret".into(),
                limit: 20,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let secret_change = changes
            .iter()
            .find(|change| change.field == "properties.secret_note")
            .unwrap();
        assert_eq!(secret_change.old_value, "[redacted]");
        assert_eq!(secret_change.new_value, "[redacted]");

        grant_object_role(&svc, "widget-secret", "tester", security::Role::Admin);
        let admin_view = svc
            .get_object(with_principal(GetObjectRequest {
                id: "widget-secret".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(admin_view.properties["secret_note"], "rotated code");

        grant_object_role(&svc, "widget-secret", "reader", security::Role::Viewer);
        svc.delete_object(with_principal(DeleteObjectRequest {
            id: "widget-secret".into(),
        }))
        .await
        .unwrap();
        let deleted_changes = svc
            .list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "widget-secret".into(),
                    limit: 20,
                    offset: 0,
                },
                "reader",
            ))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let deleted_secret_change = deleted_changes
            .iter()
            .find(|change| change.field == "properties.secret_note")
            .unwrap();
        assert_eq!(deleted_secret_change.old_value, "[redacted]");
        assert_eq!(deleted_secret_change.new_value, "[redacted]");
    }

    #[tokio::test]
    async fn action_audit_prefers_schema_classification_over_name_heuristic() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "api_key_label".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        schema_type.properties.push(PropertyDef {
            name: "secret_note".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "sensitive".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "widget-audit".into(),
                kind: "widget".into(),
                name: "widget".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "blue".into()),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "widget-audit".into()),
                    ("key".into(), "api_key_label".into()),
                    ("value".into(), "public alias".into()),
                ]),
                actor: "".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "widget-audit".into()),
                    ("key".into(), "secret_note".into()),
                    ("value".into(), "launch code".into()),
                ]),
                actor: "".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        let public_decision = decisions
            .iter()
            .find(|decision| decision.outcome.contains("api_key_label"))
            .unwrap();
        let sensitive_decision = decisions
            .iter()
            .find(|decision| decision.outcome.contains("secret_note"))
            .unwrap();
        assert_eq!(public_decision.evidence["value"], "public alias");
        assert_eq!(
            public_decision.outcome,
            "set widget-audit.api_key_label = public alias"
        );
        assert_eq!(sensitive_decision.evidence["value"], "[redacted]");
        assert_eq!(
            sensitive_decision.outcome,
            "set widget-audit.secret_note = [redacted]"
        );
    }

    #[tokio::test]
    async fn user_defined_action_type_round_trip_and_execute() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let created = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(assign_color_action()),
            }))
            .await
            .unwrap()
            .into_inner()
            .action_type
            .unwrap();
        assert_eq!(created.name, "assign_color");
        assert!(created.created > 0);

        let listed = svc
            .list_action_types(with_principal(ListActionTypesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .action_types;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "assign_color");

        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "assign_color".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: "ignored".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "blue");
        let changes = svc.db.list_object_changes("widget-1", 10, 0).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "properties.color");
        assert_eq!(changes[0].changed_by, "alice");
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("assign_color".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "alice");
        assert_eq!(decisions[0].target_id, "widget-1");

        svc.delete_action_type(with_principal(DeleteActionTypeRequest {
            name: "assign_color".into(),
        }))
        .await
        .unwrap();
        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "red".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unknown action"));
    }

    #[tokio::test]
    async fn user_defined_action_redacts_password_fixed_property_params() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "password".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "set_password".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "set_property".into(),
                    property: "password".into(),
                    value_from: "value".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_password".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("value".into(), "secret-value".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_password".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].evidence["value"], "[redacted]");
    }

    #[tokio::test]
    async fn user_defined_action_validates_params_and_authorization() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(assign_color_action()),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let missing = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([("id".into(), "widget-1".into())]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::InvalidArgument);
        assert!(missing.message().contains("missing required param: color"));

        let bad_enum = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "green".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_enum.code(), tonic::Code::InvalidArgument);
        assert!(bad_enum.message().contains("not in"));

        let denied = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert!(
            !svc.db
                .get_object("widget-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("color")
        );
    }

    #[tokio::test]
    async fn user_defined_action_rejects_undeclared_property_at_definition() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let mut action_type = assign_color_action();
        action_type.ops[0].property = "undeclared".into();

        let err = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(action_type),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
    }

    #[tokio::test]
    async fn user_defined_action_revalidates_against_current_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(assign_color_action()),
        }))
        .await
        .unwrap();
        let mut changed_schema = widget_schema_type();
        changed_schema
            .properties
            .retain(|property| property.name != "color");
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(changed_schema),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
        assert!(
            !svc.db
                .get_object("widget-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("color")
        );
    }

    #[tokio::test]
    async fn user_defined_action_rejects_undeclared_create_object_kind() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        let err = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(ActionTypeDef {
                    name: "spawn_typo".into(),
                    description: "".into(),
                    params: vec![ActionParamDef {
                        name: "child_name".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    }],
                    ops: vec![ActionOp {
                        op: "create_object".into(),
                        property: "widgte".into(),
                        value_from: "child_name".into(),
                        relation: "".into(),
                    }],
                    target_kind: "widget".into(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
    }

    #[tokio::test]
    async fn user_defined_action_rolls_back_when_later_op_fails_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "size".into(),
            r#type: "enum".into(),
            required: false,
            description: "".into(),
            enum_values: vec!["small".into(), "large".into()],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        let mut action_type = assign_color_action();
        action_type.name = "assign_color_and_size".into();
        action_type.params.push(ActionParamDef {
            name: "size".into(),
            r#type: "string".into(),
            required: true,
            enum_values: vec![],
        });
        action_type.ops.push(ActionOp {
            op: "set_property".into(),
            property: "size".into(),
            value_from: "size".into(),
            relation: "".into(),
        });
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                    ("size".into(), "small".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color_and_size".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                            ("size".into(), "medium".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "red");
        assert_eq!(obj.properties["size"], "small");
        assert!(
            svc.db
                .list_object_changes("widget-1", 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn user_defined_action_creates_object_and_link_transactionally() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let action_type = ActionTypeDef {
            name: "spawn_child".into(),
            description: "Create a child widget and link target to sibling".into(),
            params: vec![
                ActionParamDef {
                    name: "child_name".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                },
                ActionParamDef {
                    name: "to_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                },
            ],
            ops: vec![
                ActionOp {
                    op: "create_object".into(),
                    property: "widget".into(),
                    value_from: "child_name".into(),
                    relation: "".into(),
                },
                ActionOp {
                    op: "create_link".into(),
                    property: "to_id".into(),
                    value_from: "".into(),
                    relation: "relates_to".into(),
                },
            ],
            target_kind: "widget".into(),
            created: 0,
        };
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "parent".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "sibling".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "spawn_child".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("child_name".into(), "child".into()),
                        ("to_id".into(), "widget-2".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let children = svc.db.find_by_property("widget", "name", "child").unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].namespace, "");
        assert!(svc.db.get_link("widget-1->widget-2").unwrap().is_some());
        assert_eq!(
            svc.db.list_object_changes(&children[0].id, 10, 0).unwrap()[0].changed_by,
            "alice"
        );
    }

    #[tokio::test]
    async fn user_defined_action_create_link_requires_write_on_endpoint() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "link_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "to_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "create_link".into(),
                    property: "to_id".into(),
                    value_from: "".into(),
                    relation: "relates_to".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "one".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "two".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "link_widget".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("to_id".into(), "widget-2".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("widget-1->widget-2").unwrap().is_none());
    }

    #[tokio::test]
    async fn user_defined_action_deletes_link_only_when_authorized_for_both_endpoints() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "unlink_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "link_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "delete_link".into(),
                    property: "".into(),
                    value_from: "link_id".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "one".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "two".into())]),
            )))
            .unwrap();
        svc.db
            .create_link(&domain::Link {
                id: "link-1".into(),
                from_id: "widget-1".into(),
                to_id: "widget-2".into(),
                relation: "relates_to".into(),
                created: 0,
            })
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "unlink_widget".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("link_id".into(), "link-1".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        assert!(svc.db.get_link("link-1").unwrap().is_none());
    }

    #[tokio::test]
    async fn user_defined_action_delete_link_hides_unknown_link() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "unlink_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "link_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "delete_link".into(),
                    property: "".into(),
                    value_from: "link_id".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "unlink_widget".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("link_id".into(), "missing-link".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
    }

    #[tokio::test]
    async fn user_defined_action_rolls_back_created_object_when_later_link_fails() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "spawn_then_link_missing".into(),
                description: "".into(),
                params: vec![
                    ActionParamDef {
                        name: "child_name".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    },
                    ActionParamDef {
                        name: "to_id".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    },
                ],
                ops: vec![
                    ActionOp {
                        op: "create_object".into(),
                        property: "widget".into(),
                        value_from: "child_name".into(),
                        relation: "".into(),
                    },
                    ActionOp {
                        op: "create_link".into(),
                        property: "to_id".into(),
                        value_from: "".into(),
                        relation: "relates_to".into(),
                    },
                ],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "parent".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "missing", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "spawn_then_link_missing".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("child_name".into(), "child".into()),
                            ("to_id".into(), "missing".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("object not found"));
        assert!(
            svc.db
                .find_by_property("widget", "name", "child")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execute_action_allows_local_principal_on_unrestricted_object() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "local".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "local",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "local");
    }

    #[tokio::test]
    async fn execute_action_create_link_requires_write_on_both_endpoints() {
        let svc = service();
        seed_domain_object(&svc, "from-1");
        seed_domain_object(&svc, "to-1");
        grant_object_role(&svc, "from-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "to-1", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "create_link".into(),
                        params: HashMap::from([
                            ("from_id".into(), "from-1".into()),
                            ("to_id".into(), "to-1".into()),
                            ("relation".into(), "depends_on".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("from-1->to-1").unwrap().is_none());
    }

    #[tokio::test]
    async fn execute_action_delete_link_requires_write_on_both_endpoints() {
        let svc = service();
        seed_domain_object(&svc, "from-1");
        seed_domain_object(&svc, "to-1");
        svc.db
            .create_link(&domain::Link {
                id: "link-1".into(),
                from_id: "from-1".into(),
                to_id: "to-1".into(),
                relation: "depends_on".into(),
                created: 0,
            })
            .unwrap();
        grant_object_role(&svc, "from-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "to-1", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "delete_link".into(),
                        params: HashMap::from([("id".into(), "link-1".into())]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
        assert!(svc.db.get_link("link-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn execute_action_delete_link_hides_unknown_link() {
        let svc = service();

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "delete_link".into(),
                        params: HashMap::from([("id".into(), "missing-link".into())]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
    }

    #[tokio::test]
    async fn dataset_rpc_round_trip() {
        let svc = service();
        let created = svc
            .create_dataset(with_principal(CreateDatasetRequest {
                dataset: Some(Dataset {
                    id: "ds1".into(),
                    name: "metrics".into(),
                    columns: vec![ColumnDef {
                        name: "value".into(),
                        r#type: "int".into(),
                    }],
                    object_id: "".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.dataset.unwrap().id, "ds1");

        let rows = vec![
            Row {
                values: HashMap::from([("value".into(), "1".into())]),
            },
            Row {
                values: HashMap::from([("value".into(), "2".into())]),
            },
        ];
        let append = svc
            .append_rows(with_principal(AppendRowsRequest {
                dataset_id: "ds1".into(),
                rows,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(append.count, 2);

        let queried = svc
            .query_rows(with_principal(QueryRowsRequest {
                dataset_id: "ds1".into(),
                query: Some(RowQuery {
                    filters: vec![RowFilter {
                        column: "value".into(),
                        op: "gte".into(),
                        value: "2".into(),
                    }],
                    columns: vec![],
                    limit: 0,
                    offset: 0,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(queried.rows.len(), 1);
    }

    #[tokio::test]
    async fn function_rpc_round_trip() {
        let svc = service();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "c1".into(),
                kind: "component".into(),
                name: "comp".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([
                    ("language".into(), "rust".into()),
                    ("task_total".into(), "5".into()),
                ]),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "sum_tasks".into(),
                description: "".into(),
                params: vec![FuncParam {
                    name: "lang".into(),
                    r#type: "string".into(),
                    required: true,
                }],
                pipeline: vec![
                    PipelineStep {
                        op: "filter".into(),
                        kind: "component".into(),
                        property: "language".into(),
                        value: "$lang".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "sum".into(),
                        field: "task_total".into(),
                        r#as: "total".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();

        let executed = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "sum_tasks".into(),
                params: HashMap::from([("lang".into(), "rust".into())]),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(executed.result.unwrap().aggregates["total"], "5");
    }

    #[tokio::test]
    async fn computed_property_resolves_from_function_without_persisting() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "count_children".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![
                    PipelineStep {
                        op: "self".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "traverse".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "contains".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "child_count".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "cluster".into(),
                description: "Cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "count_children".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                }],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "cluster-1".into(),
                kind: "cluster".into(),
                name: "cluster".into(),
                namespace: "".into(),
                external_id: "cluster:one".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "component-1".into(),
                kind: "component".into(),
                name: "component".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
        svc.create_link(with_principal(CreateLinkRequest {
            link: Some(Link {
                id: "cluster-component".into(),
                from_id: "cluster-1".into(),
                to_id: "component-1".into(),
                relation: "contains".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "cluster-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(got.properties["child_count"], "1");

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "cluster".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["child_count"], "1");

        let stored = svc.db.get_object("cluster-1").unwrap().unwrap();
        assert!(!stored.properties.contains_key("child_count"));
    }

    #[tokio::test]
    async fn schema_type_rejects_unknown_computed_function() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(ObjectType {
                    kind: "cluster".into(),
                    description: "Cluster".into(),
                    properties: vec![PropertyDef {
                        name: "child_count".into(),
                        r#type: "computed".into(),
                        required: false,
                        description: "".into(),
                        enum_values: vec![],
                        link_kind: "".into(),
                        compute_expr: "missing_function".into(),
                        classification: "public".into(),
                        struct_fields: vec![],
                    }],
                    is_builtin: false,
                    implements: vec![],
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("missing_function"));
    }

    #[tokio::test]
    async fn unresolved_computed_property_hides_stored_value() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "ambiguous_child_count".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![
                    PipelineStep {
                        op: "self".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "first".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "second".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "cluster".into(),
                description: "Cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "ambiguous_child_count".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                }],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "cluster-spoofed".into(),
                kind: "cluster".into(),
                name: "cluster".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([("child_count".into(), "spoofed".into())]),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "cluster-spoofed".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert!(!got.properties.contains_key("child_count"));

        let stored = svc.db.get_object("cluster-spoofed").unwrap().unwrap();
        assert_eq!(stored.properties["child_count"], "spoofed");
    }

    #[tokio::test]
    async fn object_mutations_record_audit_changes() {
        let svc = service();
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: "audit-1".into(),
                    kind: "component".into(),
                    name: "api".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::from([("status".into(), "todo".into())]),
                    created: 1,
                    updated: 1,
                }),
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(Object {
                    id: "audit-1".into(),
                    kind: "component".into(),
                    name: "worker".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::from([("status".into(), "done".into())]),
                    created: 1,
                    updated: 2,
                }),
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.delete_object(with_named_principal(
            DeleteObjectRequest {
                id: "audit-1".into(),
            },
            "alice",
        ))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "audit-1".into(),
                    limit: 10,
                    offset: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert_eq!(changes.len(), 4);
        assert_eq!(
            changes
                .iter()
                .map(|change| change.field.as_str())
                .collect::<Vec<_>>(),
            vec!["_deleted", "properties.status", "name", "_created"]
        );
        assert!(changes.iter().all(|change| change.changed_by == "alice"));
        assert_eq!(changes[0].old_value, "component/worker");
        assert_eq!(changes[1].old_value, "todo");
        assert_eq!(changes[1].new_value, "done");
        assert_eq!(changes[2].old_value, "api");
        assert_eq!(changes[2].new_value, "worker");
    }

    #[tokio::test]
    async fn noop_update_does_not_record_audit_change() {
        let svc = service();
        let object = Object {
            id: "audit-noop".into(),
            kind: "component".into(),
            name: "api".into(),
            namespace: "default".into(),
            external_id: "component:api".into(),
            properties: HashMap::from([("status".into(), "todo".into())]),
            created: 1,
            updated: 1,
        };
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(object.clone()),
        }))
        .await
        .unwrap();

        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(object),
        }))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "audit-noop".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "_created");
    }

    #[tokio::test]
    async fn audit_insert_failure_rolls_back_create() {
        let svc = service();
        svc.db
            .conn()
            .execute("DROP TABLE sekai_object_changes", [])
            .unwrap();

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "audit-fail-closed".into(),
                    kind: "component".into(),
                    name: "api".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                }),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(svc.db.get_object("audit-fail-closed").unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_fails_closed_when_delete_audit_insert_fails() {
        let svc = service();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "delete-audit-fail".into(),
                kind: "component".into(),
                name: "api".into(),
                namespace: "default".into(),
                external_id: "component:api".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .conn()
            .execute("DROP TABLE sekai_object_changes", [])
            .unwrap();

        let err = svc
            .delete_object(with_principal(DeleteObjectRequest {
                id: "delete-audit-fail".into(),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(svc.db.get_object("delete-audit-fail").unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_object_remains_idempotent_when_missing() {
        let svc = service();

        svc.delete_object(with_principal(DeleteObjectRequest {
            id: "missing-object".into(),
        }))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "missing-object".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert!(changes.is_empty());
    }

    #[tokio::test]
    async fn schema_type_enforces_create_and_update() {
        let svc = service();
        grant_schema_admin(&svc);
        let created = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.r#type.unwrap().kind, "widget");

        let missing_required = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object("w1", HashMap::new())),
            }))
            .await
            .unwrap_err();
        assert_eq!(missing_required.code(), tonic::Code::InvalidArgument);
        assert!(missing_required.message().contains("name"));

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "w1",
                HashMap::from([
                    ("name".into(), "first".into()),
                    ("color".into(), "red".into()),
                ]),
            )),
        }))
        .await
        .unwrap();

        let invalid_update = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(widget_object(
                    "w1",
                    HashMap::from([
                        ("name".into(), "first".into()),
                        ("color".into(), "green".into()),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(invalid_update.code(), tonic::Code::InvalidArgument);
        assert!(invalid_update.message().contains("color"));
    }

    #[tokio::test]
    async fn untyped_kind_still_writes_and_schema_types_list() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-1".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let listed = svc
            .list_schema_types(with_principal(ListSchemaTypesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(
            listed
                .types
                .iter()
                .any(|object_type| object_type.kind == "widget" && !object_type.is_builtin)
        );
        assert!(
            listed
                .types
                .iter()
                .any(|object_type| object_type.kind == "namespace" && object_type.is_builtin)
        );
    }

    #[tokio::test]
    async fn list_schema_types_requires_principal() {
        let svc = service();
        let err = svc
            .list_schema_types(Request::new(ListSchemaTypesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn delete_schema_type_rejects_builtin() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .delete_schema_type(with_principal(DeleteSchemaTypeRequest {
                kind: "namespace".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("builtin"));
    }

    #[tokio::test]
    async fn create_schema_type_requires_schema_admin() {
        let svc = service();
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn interface_rpcs_enforce_auth_and_admin() {
        let svc = service();
        let err = svc
            .list_interfaces(Request::new(ListInterfacesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let interface = InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![],
            is_builtin: false,
        };
        let err = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface.clone()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        grant_object_role(&svc, "schema:Trackable", "tester", security::Role::Admin);
        let err = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface.clone()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        grant_object_role(&svc, "interface:Trackable", "tester", security::Role::Admin);
        let created = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface),
            }))
            .await
            .unwrap()
            .into_inner()
            .interface
            .unwrap();
        assert_eq!(created.name, "Trackable");

        let listed = svc
            .list_interfaces(with_principal(ListInterfacesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(
            listed
                .interfaces
                .iter()
                .any(|interface| interface.name == "Trackable" && !interface.is_builtin)
        );

        svc.delete_interface(with_principal(DeleteInterfaceRequest {
            name: "Trackable".into(),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delete_interface_rejects_builtin() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .delete_interface(with_principal(DeleteInterfaceRequest {
                name: "RiskScored".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("builtin"));
    }

    #[tokio::test]
    async fn schema_type_implements_interface_and_list_filters_by_interface() {
        let svc = service();
        grant_schema_admin(&svc);
        let interface = InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![PropertyDef {
                name: "tracking_id".into(),
                r#type: "string".into(),
                required: true,
                description: "".into(),
                enum_values: vec![],
                link_kind: "".into(),
                compute_expr: "".into(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
        };
        svc.create_interface(with_principal(CreateInterfaceRequest {
            interface: Some(interface),
        }))
        .await
        .unwrap();

        let mut invalid_type = widget_schema_type();
        invalid_type.implements = vec!["Trackable".into()];
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(invalid_type),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("tracking_id"));

        let mut optional_required_property = widget_schema_type();
        optional_required_property.implements = vec!["Trackable".into()];
        optional_required_property.properties.push(PropertyDef {
            name: "tracking_id".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(optional_required_property),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("must be required"));

        let mut valid_type = widget_schema_type();
        valid_type.implements = vec!["Trackable".into()];
        valid_type.properties.push(PropertyDef {
            name: "tracking_id".into(),
            r#type: "string".into(),
            required: true,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(valid_type),
        }))
        .await
        .unwrap();

        let incompatible_update = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(InterfaceDef {
                    name: "Trackable".into(),
                    description: "Trackable object".into(),
                    properties: vec![
                        PropertyDef {
                            name: "tracking_id".into(),
                            r#type: "string".into(),
                            required: true,
                            description: "".into(),
                            enum_values: vec![],
                            link_kind: "".into(),
                            compute_expr: "".into(),
                            classification: "public".into(),
                            struct_fields: vec![],
                        },
                        PropertyDef {
                            name: "second_tracking_id".into(),
                            r#type: "string".into(),
                            required: true,
                            description: "".into(),
                            enum_values: vec![],
                            link_kind: "".into(),
                            compute_expr: "".into(),
                            classification: "public".into(),
                            struct_fields: vec![],
                        },
                    ],
                    is_builtin: false,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(incompatible_update.code(), tonic::Code::InvalidArgument);
        assert!(incompatible_update.message().contains("second_tracking_id"));

        let delete_referenced = svc
            .delete_interface(with_principal(DeleteInterfaceRequest {
                name: "Trackable".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(delete_referenced.code(), tonic::Code::FailedPrecondition);

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "tracked",
                HashMap::from([
                    ("name".into(), "tracked".into()),
                    ("tracking_id".into(), "trk-1".into()),
                ]),
            )),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-2".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    interface_filter: vec!["Trackable".into()],
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.total, 1);
        assert_eq!(listed.objects[0].id, "tracked");
    }

    #[tokio::test]
    async fn corrupt_schema_row_only_blocks_that_kind_until_repaired() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                ("broken", "Broken schema", "[", 1_i64),
            )
            .unwrap();
        }
        let svc = SekaiServiceImpl::new(db.clone());
        grant_schema_admin(&svc);

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-1".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "broken-1".into(),
                    kind: "broken".into(),
                    name: "broken".into(),
                    namespace: "".into(),
                    external_id: "".into(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("broken"));

        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "broken".into(),
                description: "Repaired".into(),
                properties: vec![],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "broken-2".into(),
                kind: "broken".into(),
                name: "broken".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn user_defined_action_blocks_when_target_schema_failed_to_load() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        db.migrate_schema_types().unwrap();
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                ("broken", "Broken schema", "[", 1_i64),
            )
            .unwrap();
        }
        db.upsert_action_type(&action::ActionTypeDef {
            name: "touch_broken".into(),
            description: "".into(),
            params: vec![action::ActionParamDef {
                name: "value".into(),
                param_type: schema::PropertyType::String,
                required: true,
                enum_values: vec![],
            }],
            ops: vec![action::ActionOp {
                op: "set_property".into(),
                property: "status".into(),
                value_from: "value".into(),
                relation: "".into(),
            }],
            target_kind: "broken".into(),
            created: 1,
        })
        .unwrap();
        let svc = SekaiServiceImpl::new(db.clone());
        svc.db
            .create_object(&domain::Object {
                id: "broken-1".into(),
                kind: "broken".into(),
                name: "broken".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        grant_object_role(&svc, "broken-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "touch_broken".into(),
                        params: HashMap::from([
                            ("id".into(), "broken-1".into()),
                            ("value".into(), "done".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("broken"));
        assert!(
            !svc.db
                .get_object("broken-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("status")
        );
    }

    #[tokio::test]
    async fn schema_table_read_failure_blocks_object_writes() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_types", []).unwrap();
            conn.execute(
                "CREATE TABLE sekai_object_types (kind TEXT PRIMARY KEY)",
                [],
            )
            .unwrap();
        }
        let svc = SekaiServiceImpl::new(db.clone());

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "loose-1".into(),
                    kind: "loose".into(),
                    name: "loose".into(),
                    namespace: "".into(),
                    external_id: "".into(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("schema registry unavailable"));

        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_types", []).unwrap();
        }
        db.migrate_all().unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-2".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn malformed_object_row_returns_internal_and_next_request_succeeds() {
        let svc = service();
        {
            let conn = svc.db.conn();
            conn.execute(
                "INSERT INTO sekai_objects
                 (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                ("good", "widget", "good", "", "", "{}", 1000_i64, 1000_i64),
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sekai_objects
                 (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    "bad",
                    "widget",
                    "bad",
                    "",
                    "",
                    "{}",
                    "not-an-integer",
                    1000_i64,
                ),
            )
            .unwrap();
        }

        let err = svc
            .get_object(with_principal(GetObjectRequest { id: "bad".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);

        let good = svc
            .get_object(with_principal(GetObjectRequest { id: "good".into() }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(good.id, "good");
    }

    #[tokio::test]
    async fn delete_schema_type_removes_enforcement() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.delete_schema_type(with_principal(DeleteSchemaTypeRequest {
            kind: "widget".into(),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object("w1", HashMap::new())),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn grant_and_audit_rpcs_round_trip() {
        let svc = service();
        let admin_grant = security::Grant {
            id: "admin".into(),
            object_id: "o1".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&admin_grant).unwrap();
        svc.security.add_grant(&admin_grant);
        svc.db
            .record_decision(&audit::Decision {
                id: "d1".into(),
                timestamp: 10,
                actor: "tester".into(),
                action: "create".into(),
                reason: "".into(),
                evidence: HashMap::new(),
                target_id: "o1".into(),
                outcome: "ok".into(),
            })
            .unwrap();
        svc.db
            .record_object_change(&audit::ObjectChange {
                id: "c1".into(),
                object_id: "o1".into(),
                field: "name".into(),
                old_value: "a".into(),
                new_value: "b".into(),
                changed_by: "tester".into(),
                timestamp: 11,
            })
            .unwrap();

        let created = svc
            .create_grant(with_principal(CreateGrantRequest {
                grant: Some(Grant {
                    id: "g1".into(),
                    object_id: "o1".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.grant.unwrap().principal, "alice");

        let access = svc
            .check_access(with_principal(CheckAccessRequest {
                object_id: "o1".into(),
                principals: vec!["alice".into()],
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(access.allowed);

        let recorded = svc
            .record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: "".into(),
                    timestamp: 0,
                    actor: "tester".into(),
                    action: "gateway.budget_denied".into(),
                    reason: "budget exceeded".into(),
                    evidence: HashMap::from([("user_id".into(), "agent:codex-app".into())]),
                    target_id: "o1".into(),
                    outcome: "denied".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert!(!recorded.id.is_empty());
        assert!(recorded.timestamp > 0);

        let listed = svc
            .list_decisions(with_principal(ListDecisionsRequest {
                actor: "tester".into(),
                action: "".into(),
                after: 0,
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.decisions.len(), 2);

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "o1".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(changes.changes.len(), 1);
    }

    #[tokio::test]
    async fn coordination_rpcs_round_trip() {
        let svc = service();
        let scope = svc
            .create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: "req-scope-1".into(),
                scope: Some(ContentionScope {
                    id: "scope-1".into(),
                    name: "build".into(),
                    parent_scope_id: String::new(),
                    max_concurrency: 1,
                    admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                    heartbeat_ttl_seconds: 30,
                    timeout_seconds: 60,
                    owner_principal: String::new(),
                    created: 100,
                    updated: 100,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .scope
            .unwrap();
        assert_eq!(scope.owner_principal, "tester");

        let work_unit = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: "wu-1".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "cargo test -q".into(),
                    scope_id: "scope-1".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 101,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "idem-wu-1".into(),
                    updated_at: 101,
                }),
                request_id: "req-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(work_unit.owner_principal, "tester");

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-admit-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);
        assert_eq!(admitted.reservations.len(), 1);

        let reservations = svc
            .list_reservations(with_principal(ListReservationsRequest {
                work_unit_id: "wu-1".into(),
                scope_id: String::new(),
                status: coordination::RESERVATION_STATUS_ACTIVE.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reservations.reservations.len(), 1);

        let heartbeat = svc
            .heartbeat_work_unit(with_principal(HeartbeatWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-heartbeat-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert!(heartbeat.last_heartbeat_at > 0);

        let completed = svc
            .complete_work_unit(with_principal(CompleteWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-complete-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(completed.status, coordination::WORK_UNIT_STATUS_COMPLETED);

        let events = svc
            .list_run_events(with_principal(ListRunEventsRequest {
                work_unit_id: "wu-1".into(),
                limit: 20,
                after: 0,
                event_types: vec![],
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "created")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "admitted")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == coordination::WORK_UNIT_STATUS_COMPLETED)
        );
    }

    #[tokio::test]
    async fn coordination_hierarchy_blocks_siblings_and_snapshot_reports_contention() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "root".into(),
                name: "gradle".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 100,
                updated: 100,
            },
            ContentionScope {
                id: "child-a".into(),
                name: "gradle/a".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 101,
                updated: 101,
            },
            ContentionScope {
                id: "child-b".into(),
                name: "gradle/b".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 102,
                updated: 102,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-scope-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }
        for (id, scope_id, created_at) in [("wu-a", "child-a", 200), ("wu-b", "child-b", 201)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("run {}", id),
                    scope_id: scope_id.into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: format!("idem-{}", id),
                    updated_at: created_at,
                }),
                request_id: format!("req-{}", id),
            }))
            .await
            .unwrap();
        }

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-a".into(),
                request_id: "req-admit-wu-a".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);

        let blocked = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-b".into(),
                request_id: "req-admit-wu-b".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!blocked.admitted);
        assert!(blocked.reason.contains("saturated"));

        let snapshot = svc
            .get_coordination_snapshot(with_principal(GetCoordinationSnapshotRequest {}))
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(snapshot.pending_count, 1);
        assert_eq!(snapshot.running_count, 1);
        assert!(!snapshot.blocked_scopes.is_empty());
    }

    #[tokio::test]
    async fn coordination_create_and_transition_requests_are_idempotent() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-idem".into(),
            scope: Some(ContentionScope {
                id: "scope-idem".into(),
                name: "idem".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let create = CreateWorkUnitRequest {
            request_id: "req-create-idem".into(),
            work_unit: Some(WorkUnit {
                id: "wu-idem".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "echo hi".into(),
                scope_id: "scope-idem".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 2,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "idem-key-1".into(),
                updated_at: 2,
            }),
        };
        let first = svc
            .create_work_unit(with_principal(create.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second = svc
            .create_work_unit(with_principal(create))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(first.id, second.id);

        let admit = TryAdmitWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-admit-idem".into(),
        };
        let first_admit = svc
            .try_admit_work_unit(with_principal(admit.clone()))
            .await
            .unwrap()
            .into_inner();
        let second_admit = svc
            .try_admit_work_unit(with_principal(admit))
            .await
            .unwrap()
            .into_inner();
        assert!(first_admit.admitted);
        assert!(second_admit.admitted);

        let complete = CompleteWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-complete-idem".into(),
        };
        let first_complete = svc
            .complete_work_unit(with_principal(complete.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second_complete = svc
            .complete_work_unit(with_principal(complete))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(
            first_complete.status,
            coordination::WORK_UNIT_STATUS_COMPLETED
        );
        assert_eq!(second_complete.status, first_complete.status);
    }

    #[tokio::test]
    async fn coordination_filters_paginates_and_dry_run_reconciles() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-filter".into(),
            scope: Some(ContentionScope {
                id: "scope-filter".into(),
                name: "filter".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 10,
                updated: 10,
            }),
        }))
        .await
        .unwrap();

        for (id, key, created_at) in [("wu-f1", "filter-1", 11), ("wu-f2", "filter-2", 12)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: format!("req-create-{}", id),
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("spec {}", id),
                    scope_id: "scope-filter".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: key.into(),
                    updated_at: created_at,
                }),
            }))
            .await
            .unwrap();
        }
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-f1".into(),
            request_id: "req-admit-f1".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-f1").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-f1"],
            )
            .unwrap();

        let first_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: String::new(),
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first_page.work_units.len(), 1);
        assert!(!first_page.next_page_token.is_empty());

        let second_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: first_page.next_page_token,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second_page.work_units.len(), 1);

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: true,
                work_unit_id: "wu-f1".into(),
                scope_id: String::new(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest { id: "wu-f1".into() }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn create_work_unit_ignores_client_supplied_lifecycle_state() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-sanitize".into(),
            scope: Some(ContentionScope {
                id: "scope-sanitize".into(),
                name: "sanitize".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let created = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: "req-create-sanitize".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-sanitize".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    requested_spec: "echo hi".into(),
                    scope_id: "scope-sanitize".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 5,
                    admitted_at: 99,
                    started_at: 99,
                    finished_at: 99,
                    last_heartbeat_at: 99,
                    failure_reason: "boom".into(),
                    cancel_reason: "stop".into(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "sanitize-1".into(),
                    updated_at: 77,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();

        assert_eq!(created.status, coordination::WORK_UNIT_STATUS_PENDING);
        assert_eq!(created.admitted_at, 0);
        assert_eq!(created.started_at, 0);
        assert_eq!(created.finished_at, 0);
        assert_eq!(created.last_heartbeat_at, 0);
        assert!(created.failure_reason.is_empty());
        assert!(created.cancel_reason.is_empty());
        assert_eq!(created.updated_at, created.created_at);
    }

    #[tokio::test]
    async fn reconcile_requires_scope_ownership_for_target_scope() {
        let svc = service();
        for (scope_id, owner, created) in [("scope-a", "tester", 1), ("scope-b", "other", 2)] {
            svc.create_contention_scope(with_named_principal(
                CreateContentionScopeRequest {
                    request_id: format!("req-{}", scope_id),
                    scope: Some(ContentionScope {
                        id: scope_id.into(),
                        name: scope_id.into(),
                        parent_scope_id: String::new(),
                        max_concurrency: 1,
                        admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                        heartbeat_ttl_seconds: 1,
                        timeout_seconds: 1,
                        owner_principal: String::new(),
                        created,
                        updated: created,
                    }),
                },
                owner,
            ))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_named_principal(
            CreateWorkUnitRequest {
                request_id: "req-wu-other".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-other".into(),
                    kind: "build".into(),
                    actor: "other".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "run".into(),
                    scope_id: "scope-b".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at: 10,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "other-1".into(),
                    updated_at: 10,
                }),
            },
            "other",
        ))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_named_principal(
            TryAdmitWorkUnitRequest {
                work_unit_id: "wu-other".into(),
                request_id: "req-admit-other".into(),
            },
            "other",
        ))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-other").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-other"],
            )
            .unwrap();

        let denied = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: String::new(),
                scope_id: "scope-b".into(),
                limit: 10,
            }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let still_running = svc
            .get_work_unit(with_named_principal(
                GetWorkUnitRequest {
                    id: "wu-other".into(),
                },
                "other",
            ))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn reconcile_with_mismatched_scope_and_work_unit_returns_empty() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "scope-one".into(),
                name: "scope-one".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            },
            ContentionScope {
                id: "scope-two".into(),
                name: "scope-two".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 2,
                updated: 2,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_principal(CreateWorkUnitRequest {
            request_id: "req-wu-mismatch".into(),
            work_unit: Some(WorkUnit {
                id: "wu-mismatch".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "run".into(),
                scope_id: "scope-one".into(),
                priority: 0,
                timeout_seconds: 1,
                heartbeat_ttl_seconds: 1,
                created_at: 10,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "mismatch-1".into(),
                updated_at: 10,
            }),
        }))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-mismatch".into(),
            request_id: "req-admit-mismatch".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-mismatch").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-mismatch"],
            )
            .unwrap();

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: "wu-mismatch".into(),
                scope_id: "scope-two".into(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reconcile.work_units_reconciled, 0);
        assert_eq!(reconcile.reservations_released, 0);
        assert!(reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest {
                id: "wu-mismatch".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn list_objects_enforces_limit_and_returns_total() {
        let svc = service();
        for i in 0..1105 {
            let object = domain::Object {
                id: format!("obj-{i}"),
                kind: "query-demo".into(),
                name: format!("object-{i}"),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "backend".into())]),
                created: i64::from(i),
                updated: i64::from(i),
            };
            svc.db.create_object(&object).unwrap();
        }

        let response = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        order_by: "name".into(),
                        limit: 2000,
                        offset: 0,
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.total, 1105);
        assert_eq!(response.objects.len(), 1000);
    }

    #[tokio::test]
    async fn list_objects_omits_filter_uses_defaults() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "default-filter".into(),
                kind: "query-demo".into(),
                name: "default-filter".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "backend".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();

        let response = svc
            .list_objects(with_named_principal(
                ListObjectsRequest { filter: None },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.total, 1);
        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "default-filter");
    }

    #[tokio::test]
    async fn list_objects_rejects_unknown_property_operator() {
        let svc = service();
        let err = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team".into(),
                            op: "nope".into(),
                            value: "backend".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_objects_rejects_invalid_property_key() {
        let svc = service();
        let err = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team.name".into(),
                            op: "eq".into(),
                            value: "backend".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn object_sets_resolve_like_inline_filter_and_owner_only_access() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "owner-visible".into(),
                kind: "query-demo".into(),
                name: "owner-visible".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "alpha".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        grant_object_role(&svc, "owner-visible", "alice", security::Role::Viewer);

        svc.db
            .create_object(&domain::Object {
                id: "other-visible".into(),
                kind: "query-demo".into(),
                name: "other-visible".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "alpha".into())]),
                created: 2,
                updated: 2,
            })
            .unwrap();
        grant_object_role(&svc, "other-visible", "bob", security::Role::Viewer);

        let inline = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team".into(),
                            op: "eq".into(),
                            value: "alpha".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let created_set = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "alpha-set".into(),
                        description: "only alpha objects".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            property_filters: vec![PropertyFilter {
                                key: "team".into(),
                                op: "eq".into(),
                                value: "alpha".into(),
                            }],
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        let set_id = created_set.object_set.unwrap().id;

        let resolved_by_owner = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: set_id.clone(),
                    limit: 10,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let resolved_owner_ids = resolved_by_owner
            .objects
            .iter()
            .map(|obj| obj.id.clone())
            .collect::<Vec<_>>();

        assert_eq!(inline.total, 1);
        assert_eq!(resolved_by_owner.total, inline.total);
        assert_eq!(resolved_owner_ids, vec!["owner-visible"]);

        let err = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: set_id,
                    limit: 10,
                    offset: Some(0),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn delete_object_set_prevents_future_resolve() {
        let svc = service();
        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "temp".into(),
                        description: "temp set".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        svc.delete_object_set(with_named_principal(
            DeleteObjectSetRequest {
                id: created.id.clone(),
            },
            "alice",
        ))
        .await
        .unwrap();

        let err = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 10,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn create_object_set_rejects_duplicate_name_for_same_owner() {
        let svc = service();
        let payload = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: String::new(),
                name: "dup-name".into(),
                description: "first".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };

        svc.create_object_set(with_named_principal(payload.clone(), "alice"))
            .await
            .unwrap();

        let err = svc
            .create_object_set(with_named_principal(payload, "alice"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn create_object_set_rejects_duplicate_id_for_same_owner() {
        let svc = service();
        let first = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: "fixed-id".into(),
                name: "first-id".into(),
                description: "first".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };
        svc.create_object_set(with_named_principal(first.clone(), "alice"))
            .await
            .unwrap();

        let second = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: "fixed-id".into(),
                name: "second-id".into(),
                description: "second".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };

        let err = svc
            .create_object_set(with_named_principal(second, "alice"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn create_object_set_rejects_blank_name() {
        let svc = service();
        let err = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "  ".into(),
                        description: "blank".into(),
                        filter: Some(ListFilter::default()),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_object_set_rejects_invalid_property_key() {
        let svc = service();
        let err = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "invalid-key".into(),
                        description: "invalid filter".into(),
                        filter: Some(ListFilter {
                            property_filters: vec![PropertyFilter {
                                key: "team.name".into(),
                                op: "eq".into(),
                                value: "backend".into(),
                            }],
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resolve_object_set_offset_zero_overrides_stored_offset() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "first".into(),
                kind: "query-demo".into(),
                name: "first".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "second".into(),
                kind: "query-demo".into(),
                name: "second".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 2,
                updated: 2,
            })
            .unwrap();

        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "offset-set".into(),
                        description: "offset override".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            order_by: "name".into(),
                            limit: 1,
                            offset: 1,
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        let response = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 1,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "first");
    }

    #[tokio::test]
    async fn resolve_object_set_omitted_offset_uses_stored_offset() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "first".into(),
                kind: "query-demo".into(),
                name: "first".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "second".into(),
                kind: "query-demo".into(),
                name: "second".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 2,
                updated: 2,
            })
            .unwrap();

        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "stored-offset-set".into(),
                        description: "stored offset".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            order_by: "name".into(),
                            limit: 1,
                            offset: 1,
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        let response = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 1,
                    offset: None,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "second");
    }

    #[tokio::test]
    async fn action_policy_set_get_list_round_trip() {
        let svc = service();
        grant_action_admin(&svc);

        let policy = ActionPolicy {
            scope: "agent:codex-app".into(),
            default_decision: "allow".into(),
            action_overrides: HashMap::from([("delete_link".to_string(), "deny".to_string())]),
            risk_overrides: HashMap::from([(
                "destructive".to_string(),
                "require_approval".to_string(),
            )]),
            max_mutations_per_work_unit: 0,
            max_deletes_per_work_unit: 5,
        };

        let stored = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(policy.clone()),
            }))
            .await
            .unwrap()
            .into_inner()
            .policy
            .unwrap();
        assert_eq!(stored.scope, "agent:codex-app");
        assert_eq!(stored.action_overrides.get("delete_link").unwrap(), "deny");

        let fetched = svc
            .get_action_policy(with_principal(GetActionPolicyRequest {
                scope: "agent:codex-app".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .policy
            .unwrap();
        assert_eq!(fetched.default_decision, "allow");
        assert_eq!(
            fetched.risk_overrides.get("destructive").unwrap(),
            "require_approval"
        );
        assert_eq!(fetched.max_deletes_per_work_unit, 5);

        let listed = svc
            .list_action_policies(with_principal(ListActionPoliciesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .policies;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].scope, "agent:codex-app");
    }

    #[tokio::test]
    async fn action_policy_set_requires_action_admin() {
        let svc = service();
        // No action-admin grant for "tester".
        let err = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(ActionPolicy {
                    scope: "agent:codex-app".into(),
                    default_decision: "deny".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        // Nothing was persisted.
        assert!(
            svc.db
                .get_action_policy("agent:codex-app")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn action_policy_set_rejects_invalid_decision() {
        let svc = service();
        grant_action_admin(&svc);
        let err = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(ActionPolicy {
                    scope: "agent:codex-app".into(),
                    default_decision: "maybe".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn execute_action_denied_by_policy_is_blocked_and_audited() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny destructive ops for this agent scope.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // Create a link then attempt to delete it (destructive).
        svc.db
            .create_link(&domain::Link {
                id: "obj-1->obj-1".into(),
                from_id: "obj-1".into(),
                to_id: "obj-1".into(),
                relation: "self".into(),
                created: 0,
            })
            .unwrap();

        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "delete_link".into(),
                    params: HashMap::from([("id".into(), "obj-1->obj-1".into())]),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // Link still exists (no mutation).
        assert!(svc.db.get_link("obj-1->obj-1").unwrap().is_some());

        // Denial was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("delete_link".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "action_policy_denied");
        assert_eq!(decisions[0].evidence["risk_class"], "destructive");
        assert_eq!(decisions[0].evidence["decision"], "deny");
        assert_eq!(decisions[0].evidence["policy_scope"], "agent:tester");
    }

    #[tokio::test]
    async fn execute_action_allowed_by_policy_executes() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny only destructive; writes (set_property) are allowed.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_without_policy_is_allowed_backward_compatible() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // A deny-all policy for a *different* agent must not affect this caller.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:someone-else".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_require_approval_holds_and_returns_pending() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let mut req = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        });
        req.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::try_from("tester").unwrap(),
        );
        req.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from("wu-1").unwrap(),
        );

        let result = svc
            .execute_action(req)
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(result.decision, "require_approval");
        assert!(!result.approval_id.is_empty());

        // No mutation happened.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));

        // A pending approval was persisted with work-unit + exact params.
        let pending = svc
            .db
            .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, result.approval_id);
        assert_eq!(pending[0].action, "set_property");
        assert_eq!(pending[0].work_unit, "wu-1");
        assert_eq!(pending[0].params["value"], "done");

        // The hold was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "action_approval_pending");
    }

    #[tokio::test]
    async fn execute_action_dry_run_reports_plan_without_mutating() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");

        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();

        assert!(result.dry_run);
        assert_eq!(result.decision, "allow");
        assert_eq!(result.planned_ops, vec!["set_property obj-1.status"]);

        // No mutation happened.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));

        // A dry-run decision was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "execute_action_dry_run");
        assert_eq!(decisions[0].evidence["dry_run"], "true");
    }

    #[tokio::test]
    async fn execute_action_dry_run_surfaces_deny_without_erroring() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // Dry-run returns the plan + decision even though the policy denies.
        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(result.dry_run);
        assert_eq!(result.decision, "deny");
        assert_eq!(result.planned_ops.len(), 1);
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    fn hold_set_property(svc: &SekaiServiceImpl) -> String {
        // Set a require-approval policy and hold a set_property action.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let approval = action_approval::ActionApproval::pending(
            "tester",
            "set_property",
            HashMap::from([
                ("id".to_string(), "obj-1".to_string()),
                ("key".to_string(), "status".to_string()),
                ("value".to_string(), "done".to_string()),
            ]),
            "wu-1",
            "agent:tester",
            "write",
            "obj-1",
            1000,
        );
        svc.db.create_action_approval(&approval).unwrap();
        approval.id
    }

    #[tokio::test]
    async fn approve_action_resumes_execution_and_audits() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let response = svc
            .approve_action(with_principal(ApproveActionRequest {
                approval_id: id.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.result.unwrap().decision, "approved");
        assert_eq!(response.approval.unwrap().status, "approved");

        // The held action executed.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");

        // Approval recorded + no longer pending.
        assert!(
            svc.db
                .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
                .unwrap()
                .is_empty()
        );
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.reason == "action_approval_approved")
        );
        assert!(decisions.iter().any(|d| d.reason == "execute_action"));
    }

    #[tokio::test]
    async fn deny_action_drops_hold_without_executing() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let approval = svc
            .deny_action(with_principal(DenyActionRequest {
                approval_id: id,
                reason: "not now".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .approval
            .unwrap();
        assert_eq!(approval.status, "denied");
        assert_eq!(approval.outcome, "not now");

        // No mutation.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn approve_action_rechecks_policy_and_blocks_when_now_denied() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        // Tighten the policy to deny before approving.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let err = svc
            .approve_action(with_principal(ApproveActionRequest { approval_id: id }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        // Still not executed.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn approve_action_requires_admin() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);
        let err = svc
            .approve_action(with_principal(ApproveActionRequest { approval_id: id }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn list_pending_approvals_filters_by_status() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let pending = svc
            .list_pending_approvals(with_principal(ListPendingApprovalsRequest {
                status: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .approvals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        // Sensitive params would be redacted; here plain values pass through.
        assert_eq!(pending[0].params["value"], "done");
    }

    fn work_unit_request(
        action: &str,
        params: HashMap<String, String>,
        wu: &str,
    ) -> Request<ExecuteActionRequest> {
        let mut req = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: action.into(),
                params,
                actor: String::new(),
            }),
            dry_run: false,
        });
        req.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::try_from("tester").unwrap(),
        );
        req.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from(wu).unwrap(),
        );
        req
    }

    #[tokio::test]
    async fn blast_radius_delete_cap_hard_stops_after_limit() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Allow everything but cap deletes at 1 per work unit.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: Some(1),
            })
            .unwrap();
        for link_id in ["obj-1->a", "obj-1->b"] {
            svc.db
                .create_link(&domain::Link {
                    id: link_id.into(),
                    from_id: "obj-1".into(),
                    to_id: "obj-1".into(),
                    relation: "self".into(),
                    created: 0,
                })
                .unwrap();
        }

        // First delete within cap succeeds.
        svc.execute_action(work_unit_request(
            "delete_link",
            HashMap::from([("id".into(), "obj-1->a".into())]),
            "wu-1",
        ))
        .await
        .unwrap();

        // Second delete exceeds the cap and is hard-stopped.
        let err = svc
            .execute_action(work_unit_request(
                "delete_link",
                HashMap::from([("id".into(), "obj-1->b".into())]),
                "wu-1",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        // The second link still exists.
        assert!(svc.db.get_link("obj-1->b").unwrap().is_some());

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("delete_link".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.reason == "action_blast_radius_exceeded")
        );
    }

    #[tokio::test]
    async fn blast_radius_counters_are_scoped_per_work_unit() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: Some(1),
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // First mutation on wu-1 succeeds.
        svc.execute_action(work_unit_request(
            "set_property",
            HashMap::from([
                ("id".into(), "obj-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), "a".into()),
            ]),
            "wu-1",
        ))
        .await
        .unwrap();

        // Second mutation on wu-1 exceeds the cap.
        let err = svc
            .execute_action(work_unit_request(
                "set_property",
                HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "b".into()),
                ]),
                "wu-1",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // A different work unit has its own counter and succeeds.
        svc.execute_action(work_unit_request(
            "set_property",
            HashMap::from([
                ("id".into(), "obj-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), "c".into()),
            ]),
            "wu-2",
        ))
        .await
        .unwrap();
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "c");
    }

    #[tokio::test]
    async fn action_class_budget_denies_when_exhausted() {
        use crate::chisei::budget::{BudgetTracker, PeriodType};
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let budget = Arc::new(BudgetTracker::new());
        // Allow 1 write action, then deny.
        budget.set_limit("action:write", 1, PeriodType::Daily);
        let svc = SekaiServiceImpl::with_budget(db, budget.clone());
        seed_domain_object(&svc, "obj-1");

        // First write consumes the budget.
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "a".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        // Second write is denied by the exhausted budget.
        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "b".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // Usage reflects exactly one recorded action.
        assert_eq!(budget.get_usage("action:write").tokens_used, 1);

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.reason == "action_budget_exceeded")
        );
    }

    #[tokio::test]
    async fn governed_tool_call_is_policy_checked_via_execute_action() {
        use crate::sekai::tool_bridge::ToolCall;

        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny destructive tool-calls for this agent.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        svc.db
            .create_link(&domain::Link {
                id: "obj-1->obj-1".into(),
                from_id: "obj-1".into(),
                to_id: "obj-1".into(),
                relation: "self".into(),
                created: 0,
            })
            .unwrap();

        // An allowed write tool-call funnels through ExecuteAction and runs.
        let write_call = ToolCall::from_json_arguments(
            "set_property",
            r#"{"id":"obj-1","key":"status","value":"done"}"#,
        )
        .unwrap();
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: write_call.action_name().to_string(),
                params: write_call.to_action_params().unwrap(),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        assert_eq!(
            svc.db.get_object("obj-1").unwrap().unwrap().properties["status"],
            "done"
        );

        // A destructive tool-call is denied by policy at the same boundary.
        let delete_call =
            ToolCall::from_json_arguments("delete_link", r#"{"id":"obj-1->obj-1"}"#).unwrap();
        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: delete_call.action_name().to_string(),
                    params: delete_call.to_action_params().unwrap(),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("obj-1->obj-1").unwrap().is_some());
    }
}
