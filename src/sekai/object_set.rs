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

pub const CONTRACT_VERSION: &str = "sekai.object-set/v1";
pub const MAX_PROPERTY_FILTERS: usize = 4;
pub const MAX_EVALUATE_LIMIT: i32 = domain::MAX_LIST_LIMIT;
pub const DEFAULT_EVALUATE_LIMIT: i32 = domain::DEFAULT_LIST_LIMIT;

const ALLOWED_OPERATORS: &[&str] = &["eq", "gt", "gte", "lt", "lte"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectSetError {
    InvalidArgument(String),
    Stale(&'static str),
    Unsupported(&'static str),
}

impl ObjectSetError {
    pub fn message(&self) -> String {
        match self {
            Self::InvalidArgument(message) => message.clone(),
            Self::Stale(message) | Self::Unsupported(message) => (*message).into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSetTraversal {
    pub relation: String,
    pub direction: String,
    pub far_kind: String,
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
        if self.contract_version != CONTRACT_VERSION {
            return Err(ObjectSetError::Unsupported(
                "unsupported object-set contract version",
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
        let member_kind = if let Some(traversal) = &self.traversal {
            prepare_traversal(members, &self.kind, traversal)?
        } else {
            self.kind.clone()
        };
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
    if let Some(traversal) = &descriptor.traversal {
        hasher.update(traversal.relation.as_bytes());
        hasher.update(traversal.direction.as_bytes());
        hasher.update(traversal.far_kind.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
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
            }),
        }
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
