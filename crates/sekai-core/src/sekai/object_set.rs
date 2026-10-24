//! Revision-bound ObjectSet descriptors (#835).
//!
//! `EvaluateObjectSet` is a projection over already-authorized list and
//! one-hop traverse. A descriptor, page, or cached set is never authority.

use crate::domain::{self, ListFilter, PropertyFilter, is_valid_property_key};
use crate::sekai::definition_branch::DefinitionMember;
use crate::sekai::object_security::object_query_digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const CONTRACT_VERSION: &str = "sekai.object-set/v1";
pub const CONTRACT_VERSION_V2: &str = "sekai.object-set/v2";
pub const MAX_PROPERTY_FILTERS: usize = 4;
pub const MAX_EVALUATE_LIMIT: i32 = domain::MAX_LIST_LIMIT;
pub const DEFAULT_EVALUATE_LIMIT: i32 = domain::DEFAULT_LIST_LIMIT;
pub const MAX_HOPS: usize = 3;
pub const DEFAULT_MAX_ROWS_SCANNED: i32 = 10_000;
pub const DEFAULT_MAX_DEPTH: i32 = 3;

const ALLOWED_OPERATORS: &[&str] = &["eq", "gt", "gte", "lt", "lte"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectSetError {
    InvalidArgument(String),
    Stale(&'static str),
    Unsupported(&'static str),
    LimitExceeded(String),
}

impl ObjectSetError {
    pub fn message(&self) -> String {
        match self {
            Self::InvalidArgument(message) | Self::LimitExceeded(message) => message.clone(),
            Self::Stale(message) | Self::Unsupported(message) => (*message).into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSetTraversal {
    pub relation: String,
    pub direction: String,
    pub far_kind: String,
    pub join_property: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSetAggregation {
    pub function: String,
    pub property: String,
    pub group_by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSetCostLimit {
    pub max_rows_scanned: i32,
    pub max_depth: i32,
    pub max_time_ms: i64,
}

impl ObjectSetCostLimit {
    pub fn resolved(&self) -> Self {
        Self {
            max_rows_scanned: if self.max_rows_scanned <= 0 {
                DEFAULT_MAX_ROWS_SCANNED
            } else {
                self.max_rows_scanned
            },
            max_depth: if self.max_depth <= 0 {
                DEFAULT_MAX_DEPTH
            } else {
                self.max_depth
            },
            max_time_ms: self.max_time_ms.max(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectSetAggregateRow {
    pub group_key: String,
    pub value: f64,
    pub count: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectSetDescriptor {
    pub contract_version: String,
    pub namespace: String,
    pub kind: String,
    pub definition_digest: String,
    pub property_filters: Vec<PropertyFilter>,
    pub order_by: String,
    pub descending: bool,
    pub limit: i32,
    pub traversal: Option<ObjectSetTraversal>,
    pub hops: Vec<ObjectSetTraversal>,
    pub aggregation: Option<ObjectSetAggregation>,
    pub cost_limit: ObjectSetCostLimit,
}

#[derive(Debug, Clone)]
pub struct BoundObjectSet {
    pub descriptor: ObjectSetDescriptor,
    pub filter: ListFilter,
    pub query_digest: String,
    pub member_kind: String,
}

impl ObjectSetDescriptor {
    pub fn prepare(
        self,
        published_digest: &str,
        members: &[DefinitionMember],
    ) -> Result<BoundObjectSet, ObjectSetError> {
        let v2 = self.contract_version == CONTRACT_VERSION_V2;
        if self.contract_version != CONTRACT_VERSION && !v2 {
            return Err(ObjectSetError::Unsupported(
                "unsupported object-set contract version",
            ));
        }
        if !v2
            && (self.aggregation.is_some()
                || !self.hops.is_empty()
                || self.cost_limit.max_rows_scanned > 0
                || self.cost_limit.max_depth > 0
                || self.cost_limit.max_time_ms > 0)
        {
            return Err(ObjectSetError::Unsupported(
                "object-set aggregation and extra hops require sekai.object-set/v2",
            ));
        }
        if self.namespace.trim().is_empty() {
            return Err(ObjectSetError::InvalidArgument("namespace required".into()));
        }
        if self.kind.trim().is_empty() || !is_valid_kind(&self.kind) {
            return Err(ObjectSetError::InvalidArgument(
                "object-set kind is invalid".into(),
            ));
        }
        if self.definition_digest.trim().is_empty() {
            return Err(ObjectSetError::InvalidArgument(
                "definition_digest required".into(),
            ));
        }
        if self.definition_digest != published_digest {
            return Err(ObjectSetError::Stale(
                "object set definition revision is stale",
            ));
        }
        if self.property_filters.len() > MAX_PROPERTY_FILTERS {
            return Err(ObjectSetError::Unsupported(
                "object-set property filter count exceeds the documented subset",
            ));
        }
        if self.limit < 0 || self.limit > MAX_EVALUATE_LIMIT {
            return Err(ObjectSetError::Unsupported(
                "object-set limit exceeds the documented bound",
            ));
        }
        let object_type =
            member(members, "object_type", &self.kind).ok_or(ObjectSetError::InvalidArgument(
                "object-set kind is not in the pinned definition".into(),
            ))?;
        let mut filters = Vec::with_capacity(self.property_filters.len());
        for filter in &self.property_filters {
            filters.push(prepare_property_filter(object_type, filter)?);
        }
        let order_by = prepare_order_by(object_type, &self.order_by)?;
        let hops = resolved_hops(&self);
        if hops.len() > MAX_HOPS {
            return Err(ObjectSetError::Unsupported(
                "object-set hop count exceeds the documented bound",
            ));
        }
        let cost = self.cost_limit.resolved();
        if hops.len() as i32 > cost.max_depth {
            return Err(ObjectSetError::LimitExceeded(
                "cost limit: max_depth".into(),
            ));
        }
        let mut near = self.kind.clone();
        for hop in &hops {
            near = prepare_traversal(members, &near, hop)?;
        }
        if let Some(aggregation) = &self.aggregation {
            prepare_aggregation(aggregation)?;
        }
        let member_kind = near;
        let filter = ListFilter {
            kind: Some(self.kind.clone()),
            name: None,
            namespace: Some(self.namespace.clone()),
            property_filters: filters,
            interface_filter: Vec::new(),
            limit: if self.limit == 0 {
                DEFAULT_EVALUATE_LIMIT
            } else {
                self.limit
            },
            offset: 0,
            order_by,
            descending: self.descending,
        };
        let query_digest = descriptor_query_digest(&self, &filter)?;
        Ok(BoundObjectSet {
            descriptor: self,
            filter,
            query_digest,
            member_kind,
        })
    }
}

pub fn descriptor_query_digest(
    descriptor: &ObjectSetDescriptor,
    filter: &ListFilter,
) -> Result<String, ObjectSetError> {
    let list_digest = object_query_digest(filter).map_err(ObjectSetError::InvalidArgument)?;
    let mut hasher = Sha256::new();
    hasher.update(CONTRACT_VERSION.as_bytes());
    hasher.update(descriptor.definition_digest.as_bytes());
    hasher.update(list_digest.as_bytes());
    for hop in resolved_hops(descriptor) {
        hasher.update(hop.relation.as_bytes());
        hasher.update(hop.direction.as_bytes());
        hasher.update(hop.far_kind.as_bytes());
        hasher.update(hop.join_property.as_bytes());
    }
    if let Some(aggregation) = &descriptor.aggregation {
        hasher.update(aggregation.function.as_bytes());
        hasher.update(aggregation.property.as_bytes());
        hasher.update(aggregation.group_by.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn resolved_hops(descriptor: &ObjectSetDescriptor) -> Vec<ObjectSetTraversal> {
    if !descriptor.hops.is_empty() {
        return descriptor.hops.clone();
    }
    descriptor.traversal.clone().into_iter().collect()
}

fn prepare_aggregation(aggregation: &ObjectSetAggregation) -> Result<(), ObjectSetError> {
    let function = aggregation.function.trim().to_ascii_lowercase();
    if !matches!(
        function.as_str(),
        "count" | "sum" | "min" | "max" | "avg" | "distinct"
    ) {
        return Err(ObjectSetError::Unsupported(
            "unsupported object-set aggregation function",
        ));
    }
    if function != "count" && aggregation.property.trim().is_empty() {
        return Err(ObjectSetError::InvalidArgument(
            "aggregation property required".into(),
        ));
    }
    if aggregation.group_by.trim().is_empty() {
        return Err(ObjectSetError::InvalidArgument(
            "aggregation group_by required".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct CostMeter {
    pub rows: i32,
    pub started: std::time::Instant,
    pub limit: ObjectSetCostLimit,
}

impl CostMeter {
    pub fn new(limit: ObjectSetCostLimit) -> Self {
        Self {
            rows: 0,
            started: std::time::Instant::now(),
            limit: limit.resolved(),
        }
    }

    pub fn charge(&mut self, rows: i32) -> Result<(), ObjectSetError> {
        self.rows = self.rows.saturating_add(rows.max(0));
        if self.rows > self.limit.max_rows_scanned {
            return Err(ObjectSetError::LimitExceeded(
                "cost limit: max_rows_scanned".into(),
            ));
        }
        if self.limit.max_time_ms > 0
            && self.started.elapsed().as_millis() as i64 > self.limit.max_time_ms
        {
            return Err(ObjectSetError::LimitExceeded(
                "cost limit: max_time_ms".into(),
            ));
        }
        Ok(())
    }
}

/// Group leaf numeric values. Hidden or non-numeric properties are omitted
/// from the value list and are indistinguishable from absence.
pub fn aggregate_groups(
    rows: &[(String, Option<f64>)],
    function: &str,
) -> Result<Vec<ObjectSetAggregateRow>, ObjectSetError> {
    let function = function.trim().to_ascii_lowercase();
    let mut grouped: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for (group, value) in rows {
        if let Some(number) = value {
            grouped.entry(group.clone()).or_default().push(*number);
        } else if function == "count" {
            grouped.entry(group.clone()).or_default();
        }
    }
    let mut out = Vec::new();
    for (group_key, values) in grouped {
        let count = values.len() as i64;
        let value = match function.as_str() {
            "count" => count as f64,
            "sum" => values.iter().sum(),
            "min" => values.iter().copied().fold(f64::INFINITY, f64::min),
            "max" => values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            "avg" => {
                if values.is_empty() {
                    0.0
                } else {
                    values.iter().sum::<f64>() / values.len() as f64
                }
            }
            "distinct" => {
                let mut unique = values;
                unique.sort_by(|left, right| {
                    left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal)
                });
                unique.dedup();
                unique.len() as f64
            }
            _ => {
                return Err(ObjectSetError::Unsupported(
                    "unsupported object-set aggregation function",
                ));
            }
        };
        out.push(ObjectSetAggregateRow {
            group_key,
            value,
            count,
        });
    }
    Ok(out)
}

fn prepare_property_filter(
    object_type: &DefinitionMember,
    filter: &PropertyFilter,
) -> Result<PropertyFilter, ObjectSetError> {
    if !is_valid_property_key(&filter.key) {
        return Err(ObjectSetError::InvalidArgument(
            "invalid property key".into(),
        ));
    }
    let op = filter.op.trim().to_ascii_lowercase();
    if !ALLOWED_OPERATORS.contains(&op.as_str()) {
        return Err(ObjectSetError::Unsupported(
            "unsupported object-set property operator",
        ));
    }
    let property_type = declared_property_type(object_type, &filter.key).ok_or(
        ObjectSetError::InvalidArgument("unknown object-set property".into()),
    )?;
    validate_property_value(&property_type, &filter.value)?;
    Ok(PropertyFilter {
        key: filter.key.clone(),
        op,
        value: filter.value.clone(),
    })
}

fn prepare_order_by(
    object_type: &DefinitionMember,
    order_by: &str,
) -> Result<String, ObjectSetError> {
    if order_by.is_empty() {
        return Ok(String::new());
    }
    let normalized = order_by.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "name" | "created" | "updated") {
        return Ok(normalized);
    }
    let Some(("property", key)) = order_by.trim().split_once(':') else {
        return Err(ObjectSetError::Unsupported(
            "unsupported object-set order_by",
        ));
    };
    if !is_valid_property_key(key) || declared_property_type(object_type, key).is_none() {
        return Err(ObjectSetError::InvalidArgument(
            "unknown object-set order_by property".into(),
        ));
    }
    Ok(format!("property:{key}"))
}

fn prepare_traversal(
    members: &[DefinitionMember],
    near_kind: &str,
    traversal: &ObjectSetTraversal,
) -> Result<String, ObjectSetError> {
    if traversal.relation.trim().is_empty() || !is_valid_kind(&traversal.relation) {
        return Err(ObjectSetError::InvalidArgument(
            "object-set traversal relation is invalid".into(),
        ));
    }
    if traversal.far_kind.trim().is_empty() || !is_valid_kind(&traversal.far_kind) {
        return Err(ObjectSetError::InvalidArgument(
            "object-set traversal far_kind is invalid".into(),
        ));
    }
    if member(members, "object_type", &traversal.far_kind).is_none() {
        return Err(ObjectSetError::InvalidArgument(
            "object-set far kind is not in the pinned definition".into(),
        ));
    }
    let direction = traversal.direction.trim();
    if !direction.is_empty() && direction != "outgoing" && direction != "incoming" {
        return Err(ObjectSetError::Unsupported(
            "unsupported object-set traversal direction",
        ));
    }
    let Some(link) = member(members, "link_type", &traversal.relation) else {
        return Err(ObjectSetError::InvalidArgument(
            "object-set traversal is not a declared link".into(),
        ));
    };
    let value: Value = serde_json::from_str(&link.definition_json)
        .map_err(|_| ObjectSetError::InvalidArgument("declared link is invalid".into()))?;
    if let Some(from) = value.get("from").and_then(Value::as_str)
        && from != near_kind
        && direction != "incoming"
    {
        return Err(ObjectSetError::InvalidArgument(
            "object-set traversal does not match the declared link".into(),
        ));
    }
    if let Some(to) = value.get("to").and_then(Value::as_str)
        && to != traversal.far_kind
        && direction != "incoming"
    {
        return Err(ObjectSetError::InvalidArgument(
            "object-set traversal does not match the declared link".into(),
        ));
    }
    Ok(traversal.far_kind.clone())
}

fn declared_property_type(object_type: &DefinitionMember, key: &str) -> Option<String> {
    let value: Value = serde_json::from_str(&object_type.definition_json).ok()?;
    match value.get("properties")? {
        Value::Object(properties) => properties.get(key).map(|declared| {
            declared
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("string")
                .to_ascii_lowercase()
        }),
        Value::Array(properties) => properties
            .iter()
            .any(|item| item.as_str() == Some(key))
            .then(|| "string".into()),
        _ => None,
    }
}

fn validate_property_value(property_type: &str, value: &str) -> Result<(), ObjectSetError> {
    match property_type {
        "integer" | "int" | "number" => {
            if value.parse::<i64>().is_ok() || value.parse::<f64>().is_ok() {
                Ok(())
            } else {
                Err(ObjectSetError::InvalidArgument(
                    "object-set property value has the wrong type".into(),
                ))
            }
        }
        "boolean" | "bool" => {
            if matches!(value, "true" | "false") {
                Ok(())
            } else {
                Err(ObjectSetError::InvalidArgument(
                    "object-set property value has the wrong type".into(),
                ))
            }
        }
        "string" | "text" => Ok(()),
        _ => Err(ObjectSetError::Unsupported(
            "unsupported object-set property type",
        )),
    }
}

fn member<'a>(
    members: &'a [DefinitionMember],
    kind: &str,
    id: &str,
) -> Option<&'a DefinitionMember> {
    members
        .iter()
        .find(|member| member.member_kind == kind && member.member_id == id)
}

fn is_valid_kind(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };

    fn catalog() -> (String, Vec<DefinitionMember>) {
        let members = [
            member_input(
                "Customer",
                r#"{"name":"Customer","properties":{"region":{"type":"string"},"tier":{"type":"integer"}}}"#,
            ),
            member_input(
                "Order",
                r#"{"name":"Order","properties":{"status":{"type":"string"}}}"#,
            ),
        ];
        let link = DefinitionMemberInput {
            member_kind: "link_type".into(),
            member_id: "placed".into(),
            definition_json: r#"{"name":"placed","from":"Customer","to":"Order"}"#.into(),
            member_digest: String::new(),
        }
        .prepare("sales")
        .unwrap();
        let mut all = members.to_vec();
        all.push(link);
        let revision = prepare_revision(
            "sales",
            "",
            all.iter().map(|item| DefinitionRevisionMember {
                member_kind: item.member_kind.clone(),
                member_id: item.member_id.clone(),
                member_digest: item.member_digest.clone(),
            }),
            true,
            "author",
            1,
        )
        .unwrap();
        (revision.revision_digest, all)
    }

    fn member_input(id: &str, json: &str) -> DefinitionMember {
        DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare("sales")
        .unwrap()
    }

    fn descriptor(digest: &str) -> ObjectSetDescriptor {
        ObjectSetDescriptor {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            definition_digest: digest.into(),
            property_filters: vec![
                PropertyFilter {
                    key: "region".into(),
                    op: "eq".into(),
                    value: "eu".into(),
                },
                PropertyFilter {
                    key: "tier".into(),
                    op: "gte".into(),
                    value: "2".into(),
                },
            ],
            order_by: "property:tier".into(),
            descending: true,
            limit: 2,
            traversal: Some(ObjectSetTraversal {
                relation: "placed".into(),
                direction: "outgoing".into(),
                far_kind: "Order".into(),
                join_property: String::new(),
            }),
            hops: Vec::new(),
            aggregation: None,
            cost_limit: ObjectSetCostLimit::default(),
        }
    }

    #[test]
    fn aggregate_groups_omit_missing_values_like_hidden_properties() {
        let rows = vec![
            ("c1".into(), Some(10.0)),
            ("c1".into(), None),
            ("c2".into(), Some(5.0)),
        ];
        let sums = aggregate_groups(&rows, "sum").unwrap();
        assert_eq!(sums.len(), 2);
        let c1 = sums.iter().find(|row| row.group_key == "c1").unwrap();
        assert_eq!(c1.value, 10.0);
        assert_eq!(c1.count, 1);
    }

    #[test]
    fn cost_meter_names_the_exceeded_limit() {
        let mut meter = CostMeter::new(ObjectSetCostLimit {
            max_rows_scanned: 2,
            max_depth: 3,
            max_time_ms: 0,
        });
        meter.charge(2).unwrap();
        let error = meter.charge(1).unwrap_err();
        assert!(
            matches!(error, ObjectSetError::LimitExceeded(message) if message == "cost limit: max_rows_scanned")
        );
    }

    #[test]
    fn pins_published_digest_and_declared_link() {
        let (digest, members) = catalog();
        let bound = descriptor(&digest).prepare(&digest, &members).unwrap();
        assert_eq!(bound.member_kind, "Order");
        assert_eq!(bound.filter.kind.as_deref(), Some("Customer"));
        assert_eq!(bound.filter.property_filters.len(), 2);
        assert_eq!(bound.filter.order_by, "property:tier");
        assert_eq!(bound.filter.limit, 2);
    }

    #[test]
    fn stale_definition_and_unsupported_operator_fail_closed() {
        let (digest, members) = catalog();
        let stale = descriptor("sha256:dead")
            .prepare(&digest, &members)
            .unwrap_err();
        assert!(matches!(stale, ObjectSetError::Stale(_)));
        let mut unknown = descriptor(&digest);
        unknown.property_filters[0].op = "contains".into();
        assert!(matches!(
            unknown.prepare(&digest, &members),
            Err(ObjectSetError::Unsupported(_))
        ));
        let mut wrong_type = descriptor(&digest);
        wrong_type.property_filters[1].value = "gold".into();
        assert!(matches!(
            wrong_type.prepare(&digest, &members),
            Err(ObjectSetError::InvalidArgument(_))
        ));
    }

    #[test]
    fn undeclared_link_and_excessive_size_fail() {
        let (digest, members) = catalog();
        let mut hop = descriptor(&digest);
        hop.traversal.as_mut().unwrap().relation = "owns".into();
        assert!(matches!(
            hop.prepare(&digest, &members),
            Err(ObjectSetError::InvalidArgument(_))
        ));
        let mut deep = descriptor(&digest);
        deep.limit = MAX_EVALUATE_LIMIT + 1;
        assert!(matches!(
            deep.prepare(&digest, &members),
            Err(ObjectSetError::Unsupported(_))
        ));
    }
}
