//! Pluggable object-index engines for EvaluateObjectSet hops (#889).
//!
//! `hop-projection` is the shipping default: a rebuildable join-key
//! projection from the #889 envelope. `nested-loop` is the original
//! in-process scan, kept as an explicit debug engine. Neither is object
//! authority. Switching engines is a rebuild of the join projection.

use crate::sekai::object_type_index::ObjectTypeIndexMember;
use std::collections::{HashMap, HashSet};
use std::env;

pub const NESTED_LOOP: &str = "nested-loop";
pub const HOP_PROJECTION: &str = "hop-projection";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectIndexEngineKind {
    NestedLoop,
    HopProjection,
}

impl ObjectIndexEngineKind {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            NESTED_LOOP => Ok(Self::NestedLoop),
            HOP_PROJECTION | "" => Ok(Self::HopProjection),
            other => Err(format!(
                "unsupported SEKAI_OBJECT_INDEX_ENGINE {other:?}; expected {NESTED_LOOP} or {HOP_PROJECTION}"
            )),
        }
    }

    pub fn from_env() -> Self {
        match env::var("SEKAI_OBJECT_INDEX_ENGINE") {
            Ok(value) if !value.trim().is_empty() => Self::parse(&value).unwrap_or_else(|error| {
                tracing::warn!(
                    error = %error,
                    "invalid object index engine; using hop-projection"
                );
                Self::HopProjection
            }),
            _ => Self::HopProjection,
        }
    }

    pub fn dual_read_from_env() -> bool {
        env::var("SEKAI_OBJECT_INDEX_DUAL_READ").unwrap_or_default() == "1"
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NestedLoop => NESTED_LOOP,
            Self::HopProjection => HOP_PROJECTION,
        }
    }
}

pub fn join_paths_nested<'a>(
    paths: Vec<Vec<&'a ObjectTypeIndexMember>>,
    children: &'a [ObjectTypeIndexMember],
    join_property: &str,
) -> Vec<Vec<&'a ObjectTypeIndexMember>> {
    if join_property.is_empty() {
        return Vec::new();
    }
    let mut next = Vec::new();
    for path in &paths {
        let parent = path[path.len() - 1];
        for child in children {
            let matched = child
                .properties
                .get(join_property)
                .is_some_and(|value| value == &parent.source_key || value == &parent.object_id);
            if matched {
                let mut joined = path.clone();
                joined.push(child);
                next.push(joined);
            }
        }
    }
    next
}

pub fn join_paths_hash<'a>(
    paths: Vec<Vec<&'a ObjectTypeIndexMember>>,
    children: &'a [ObjectTypeIndexMember],
    join_property: &str,
) -> Vec<Vec<&'a ObjectTypeIndexMember>> {
    if join_property.is_empty() {
        return Vec::new();
    }
    let mut by_value: HashMap<&str, Vec<&ObjectTypeIndexMember>> = HashMap::new();
    for child in children {
        if let Some(value) = child.properties.get(join_property) {
            by_value.entry(value.as_str()).or_default().push(child);
        }
    }
    let mut next = Vec::new();
    for path in &paths {
        let parent = path[path.len() - 1];
        let mut seen_keys = HashSet::new();
        for key in [&parent.source_key, &parent.object_id] {
            if !seen_keys.insert(key.as_str()) {
                continue;
            }
            if let Some(matched) = by_value.get(key.as_str()) {
                for child in matched {
                    let mut joined = path.clone();
                    joined.push(*child);
                    next.push(joined);
                }
            }
        }
    }
    next
}

/// Parent/child identity used to walk the join-key projection without
/// inspecting child property maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopKey {
    pub kind: String,
    pub source_key: String,
    pub object_id: String,
}

impl HopKey {
    pub fn from_member(member: &ObjectTypeIndexMember) -> Self {
        Self {
            kind: member.kind.clone(),
            source_key: member.source_key.clone(),
            object_id: member.object_id.clone(),
        }
    }

    pub fn stub_member(&self) -> ObjectTypeIndexMember {
        ObjectTypeIndexMember {
            kind: self.kind.clone(),
            source_key: self.source_key.clone(),
            object_id: self.object_id.clone(),
            ..ObjectTypeIndexMember::default()
        }
    }
}

/// Extend key paths from join-table edges `(parent_value, child_source_key)`.
/// Child identity comes from `child_by_key`; child properties are not read.
pub fn join_key_paths(
    paths: Vec<Vec<HopKey>>,
    edges: &[(String, String)],
    child_by_key: &HashMap<String, HopKey>,
) -> Vec<Vec<HopKey>> {
    if edges.is_empty() || child_by_key.is_empty() {
        return Vec::new();
    }
    let mut children_by_parent: HashMap<&str, Vec<&str>> = HashMap::new();
    for (parent, child) in edges {
        children_by_parent
            .entry(parent.as_str())
            .or_default()
            .push(child.as_str());
    }
    let mut next = Vec::new();
    for path in paths {
        let parent = path.last().expect("path");
        let mut seen_keys = HashSet::new();
        for key in [&parent.source_key, &parent.object_id] {
            if !seen_keys.insert(key.as_str()) {
                continue;
            }
            if let Some(child_keys) = children_by_parent.get(key.as_str()) {
                for child_key in child_keys {
                    if let Some(child) = child_by_key.get(*child_key) {
                        let mut joined = path.clone();
                        joined.push(child.clone());
                        next.push(joined);
                    }
                }
            }
        }
    }
    next
}

pub fn path_signature(paths: &[Vec<&ObjectTypeIndexMember>]) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = paths
        .iter()
        .map(|path| {
            path.iter()
                .map(|member| format!("{}:{}", member.kind, member.source_key))
                .collect()
        })
        .collect();
    rows.sort();
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn member(kind: &str, key: &str, property: &str, value: &str) -> ObjectTypeIndexMember {
        ObjectTypeIndexMember {
            kind: kind.into(),
            source_key: key.into(),
            object_id: format!("{kind}:{key}"),
            properties: BTreeMap::from([(property.into(), value.into())]),
            ..ObjectTypeIndexMember::default()
        }
    }

    #[test]
    fn hash_join_matches_nested_loop_and_skips_empty_join_property() {
        let customers = [member("Customer", "c1", "region", "eu")];
        let orders = [
            member("Order", "o1", "customer_id", "c1"),
            member("Order", "o-other", "customer_id", "c2"),
        ];
        let roots: Vec<Vec<&ObjectTypeIndexMember>> =
            customers.iter().map(|member| vec![member]).collect();
        let nested = join_paths_nested(roots.clone(), &orders, "customer_id");
        let hashed = join_paths_hash(roots, &orders, "customer_id");
        assert_eq!(path_signature(&nested), path_signature(&hashed));
        assert_eq!(nested.len(), 1);
        assert!(join_paths_hash(vec![vec![&customers[0]]], &orders, "").is_empty());
    }

    #[test]
    fn join_key_paths_follows_edges_without_child_properties() {
        let customers = [member("Customer", "c1", "region", "eu")];
        let orders = [
            member("Order", "o1", "customer_id", "c1"),
            member("Order", "o-other", "customer_id", "c2"),
        ];
        let roots = vec![vec![HopKey::from_member(&customers[0])]];
        let edges = vec![("c1".into(), "o1".into())];
        let child_by_key = HashMap::from([(
            "o1".into(),
            HopKey {
                kind: "Order".into(),
                source_key: "o1".into(),
                object_id: "Order:o1".into(),
            },
        )]);
        let joined = join_key_paths(roots, &edges, &child_by_key);
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0][1].source_key, "o1");
        let hashed = join_paths_hash(
            customers.iter().map(|member| vec![member]).collect(),
            &orders,
            "customer_id",
        );
        assert_eq!(joined[0][1].source_key, hashed[0][1].source_key);
        assert!(orders[0].properties.contains_key("customer_id"));
    }

    #[test]
    fn parse_engine_names() {
        assert_eq!(
            ObjectIndexEngineKind::parse(NESTED_LOOP).unwrap(),
            ObjectIndexEngineKind::NestedLoop
        );
        assert_eq!(
            ObjectIndexEngineKind::parse(HOP_PROJECTION).unwrap(),
            ObjectIndexEngineKind::HopProjection
        );
        assert!(ObjectIndexEngineKind::parse("lucene").is_err());
        assert_eq!(
            ObjectIndexEngineKind::parse("").unwrap(),
            ObjectIndexEngineKind::HopProjection
        );
    }

    #[test]
    fn unset_engine_defaults_to_hop_projection() {
        if env::var("SEKAI_OBJECT_INDEX_ENGINE")
            .ok()
            .is_none_or(|value| value.trim().is_empty())
        {
            assert_eq!(
                ObjectIndexEngineKind::from_env(),
                ObjectIndexEngineKind::HopProjection
            );
        }
    }
}
