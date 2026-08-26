use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Link, Object};
use crate::sekai::object_security::PrincipalPolicyContext;
use crate::sekai::schema::SchemaRegistry;
use std::collections::{HashMap, HashSet, VecDeque};

const MAX_DEPTH: i32 = 10;

pub type ObjectAllowFn<'a> =
    dyn Fn(Option<&Object>, &Object) -> Result<Option<String>, String> + 'a;

#[derive(Debug, Clone, Default)]
pub struct GraphQuery {
    pub start_id: String,
    pub start_external_id: String,
    pub relations: Vec<String>,
    pub direction: Direction,
    pub max_depth: i32,
    pub kind_filter: Vec<String>,
    pub interface_filter: Vec<String>,
    pub property_filter: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct GraphResult {
    pub objects: Vec<Object>,
    pub links: Vec<Link>,
}

pub fn traverse(
    db: &RuntimeDb,
    q: &GraphQuery,
    schema: Option<&SchemaRegistry>,
) -> Result<GraphResult, String> {
    traverse_with_policy_context(db, q, schema, None, None)
}

pub fn traverse_with_policy_context(
    db: &RuntimeDb,
    q: &GraphQuery,
    schema: Option<&SchemaRegistry>,
    policy_context: Option<&PrincipalPolicyContext>,
    allow: Option<&ObjectAllowFn<'_>>,
) -> Result<GraphResult, String> {
    let start_id = if !q.start_id.is_empty() {
        q.start_id.clone()
    } else if !q.start_external_id.is_empty() {
        let found = match policy_context {
            Some(context) => db
                .find_all_by_external_id_with_policy_context(&q.start_external_id, context)?
                .into_iter()
                .next(),
            None => db.find_by_external_id(&q.start_external_id)?,
        };
        match found {
            Some(obj) => obj.id,
            None => return Ok(GraphResult::default()),
        }
    } else {
        return Err("start_id or start_external_id required".into());
    };

    let depth = q.max_depth.clamp(1, MAX_DEPTH);
    let rel_set: HashSet<&str> = q.relations.iter().map(|s| s.as_str()).collect();
    let kind_set: HashSet<&str> = q.kind_filter.iter().map(|s| s.as_str()).collect();
    // Relation set is query-stable; build the lookup list once instead of
    // reallocating owned Strings on every frontier node.
    let rels: Vec<&str> = if rel_set.is_empty() {
        vec![""]
    } else {
        rel_set.iter().copied().collect()
    };

    let mut visited = HashSet::new();
    visited.insert((start_id.clone(), String::new()));
    let mut frontier = VecDeque::new();
    frontier.push_back(start_id.clone());
    let mut seen_objects = HashMap::new();
    if let Some(start) = match policy_context {
        Some(context) => db.get_object_with_policy_context(&start_id, context)?,
        None => db.get_object(&start_id)?,
    } {
        seen_objects.insert(start_id.clone(), start);
    }
    let mut result = GraphResult::default();

    for _ in 0..depth {
        let mut next = VecDeque::new();
        while let Some(node_id) = frontier.pop_front() {
            for rel in &rels {
                let links = match policy_context {
                    Some(context) => {
                        db.get_links_with_policy_context(&node_id, rel, &q.direction, context)?
                    }
                    None => db.get_links(&node_id, rel, &q.direction)?,
                };
                for link in links {
                    let target = match &q.direction {
                        Direction::Outgoing => &link.to_id,
                        Direction::Incoming => &link.from_id,
                    };
                    let obj = match policy_context {
                        Some(context) => db.get_object_with_policy_context(target, context)?,
                        None => db.get_object(target)?,
                    };
                    let Some(obj) = obj else {
                        visited.insert((target.clone(), String::new()));
                        continue;
                    };
                    let parent = seen_objects.get(&node_id);
                    let visit_key = match allow {
                        Some(allow) => match allow(parent, &obj)? {
                            Some(key) => key,
                            None => continue,
                        },
                        None => String::new(),
                    };
                    if !visited.insert((target.clone(), visit_key)) {
                        continue;
                    }
                    next.push_back(target.clone());
                    seen_objects.insert(target.clone(), obj.clone());
                    if matches_filters(
                        &obj,
                        &kind_set,
                        &q.interface_filter,
                        &q.property_filter,
                        schema,
                    ) {
                        if !result.objects.iter().any(|seen| seen.id == obj.id) {
                            result.objects.push(obj);
                        }
                        if !result.links.iter().any(|seen| seen.id == link.id) {
                            result.links.push(link);
                        }
                    }
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    Ok(result)
}

fn matches_filters(
    obj: &Object,
    kind_set: &HashSet<&str>,
    interface_filter: &[String],
    prop_filter: &HashMap<String, String>,
    schema: Option<&SchemaRegistry>,
) -> bool {
    if !kind_set.is_empty() && !kind_set.contains(obj.kind.as_str()) {
        return false;
    }
    if !interface_filter.is_empty()
        && !schema
            .map(|schema| schema.kind_implements_all(&obj.kind, interface_filter))
            .unwrap_or(false)
    {
        return false;
    }
    for (k, v) in prop_filter {
        if obj.properties.get(k).map(|pv| pv != v).unwrap_or(true) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::KIND_COMPONENT;
    use crate::sekai::schema::{
        InterfaceDef, ObjectType, PropertyDef, PropertyType, SchemaRegistry,
    };

    fn setup() -> RuntimeDb {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        // namespace -> comp1, comp2; comp1 -> file1
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "namespace".into(),
            namespace: "".into(),
            external_id: "namespace:main".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp1".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("language".into(), "rust".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c2".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp2".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::from([("language".into(), "go".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "f1".into(),
            kind: "file".into(),
            name: "main.rs".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l2".into(),
            from_id: "r1".into(),
            to_id: "c2".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l3".into(),
            from_id: "c1".into(),
            to_id: "f1".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        db
    }

    #[test]
    fn test_single_hop() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 1,
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 2); // comp1, comp2
    }

    #[test]
    fn test_multi_hop() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 3); // comp1, comp2, file1
    }

    #[test]
    fn test_kind_filter() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            kind_filter: vec![KIND_COMPONENT.into()],
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 2); // only components
    }

    #[test]
    fn test_property_filter() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 1,
            property_filter: HashMap::from([("language".into(), "rust".into())]),
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 1);
        assert_eq!(res.objects[0].name, "comp1");
    }

    #[test]
    fn test_start_external_id() {
        let db = setup();
        let q = GraphQuery {
            start_external_id: "namespace:main".into(),
            max_depth: 1,
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 2);
    }

    #[test]
    fn test_relation_filter() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 1,
            relations: vec!["owns".into()],
            ..Default::default()
        };
        let res = traverse(&db, &q, None).unwrap();
        assert_eq!(res.objects.len(), 0); // no "owns" links
    }

    #[test]
    fn traverse_allow_receives_parent_and_can_deny_hops() {
        let db = setup();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            ..Default::default()
        };
        let res = traverse_with_policy_context(
            &db,
            &q,
            None,
            None,
            Some(&|parent, object| {
                Ok(
                    (parent.is_some_and(|parent| parent.id == "r1") && object.id != "c2")
                        .then(|| "ok".into()),
                )
            }),
        )
        .unwrap();
        let ids = res
            .objects
            .iter()
            .map(|object| object.id.as_str())
            .collect::<Vec<_>>();
        assert!(ids.contains(&"c1"));
        assert!(!ids.contains(&"c2"));
        assert!(!ids.contains(&"f1"));
    }

    #[test]
    fn traverse_retries_target_after_denied_first_hop() {
        let db = setup();
        db.create_link(&Link {
            id: "l4".into(),
            from_id: "c2".into(),
            to_id: "f1".into(),
            relation: "contains".into(),
            created: 0,
        })
        .unwrap();
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            ..Default::default()
        };
        let res = traverse_with_policy_context(
            &db,
            &q,
            None,
            None,
            Some(&|parent, object| {
                Ok(
                    (!(parent.is_some_and(|parent| parent.id == "c1") && object.id == "f1"))
                        .then(|| parent.map(|parent| parent.id.clone()).unwrap_or_default()),
                )
            }),
        )
        .unwrap();
        let ids = res
            .objects
            .iter()
            .map(|object| object.id.as_str())
            .collect::<Vec<_>>();
        assert!(
            ids.contains(&"f1"),
            "a later permitted hop must still reach f1"
        );
    }

    #[test]
    fn test_interface_filter() {
        let db = setup();
        let mut schema = SchemaRegistry::new();
        schema.register_interface(InterfaceDef {
            name: "RiskScored".into(),
            description: "Risk scored".into(),
            properties: vec![],
            is_builtin: false,
        });
        schema.register(ObjectType {
            kind: KIND_COMPONENT.into(),
            description: "Component".into(),
            properties: vec![PropertyDef {
                name: "language".into(),
                prop_type: PropertyType::String,
                required: false,
                description: String::new(),
                enum_values: vec![],
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: crate::sekai::schema::default_property_classification(),
                struct_fields: vec![],
            }],
            is_builtin: false,
            implements: vec!["RiskScored".into()],
        });
        let q = GraphQuery {
            start_id: "r1".into(),
            max_depth: 2,
            interface_filter: vec!["RiskScored".into()],
            property_filter: HashMap::from([("language".into(), "rust".into())]),
            ..Default::default()
        };
        let res = traverse(&db, &q, Some(&schema)).unwrap();
        assert_eq!(res.objects.len(), 1);
        assert_eq!(res.objects[0].id, "c1");
    }
}
