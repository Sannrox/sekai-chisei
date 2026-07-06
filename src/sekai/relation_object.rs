use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Object, REL_RELATION_SOURCE, REL_RELATION_TARGET, Relation};
use rusqlite::{OptionalExtension, params};
use std::collections::{HashMap, HashSet};

pub const KIND_RELATIONSHIP: &str = "relationship";
pub const PROP_SOURCE_ID: &str = "source_id";
pub const PROP_TARGET_ID: &str = "target_id";
pub const PROP_RELATION: &str = "relation";
pub const PROP_STATUS: &str = "status";
pub const PROP_ROLE: &str = "role";
pub const PROP_CONFIDENCE: &str = "confidence";
pub const PROP_VALID_FROM: &str = "valid_from";
pub const PROP_VALID_TO: &str = "valid_to";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Source,
    Target,
    Either,
}

#[derive(Debug, Clone)]
pub struct RelationshipObjectSpec {
    pub id: String,
    pub relation: Relation,
    pub source_id: String,
    pub target_id: String,
    pub status: String,
    pub role: String,
    pub confidence: Option<f64>,
    pub valid_from: String,
    pub valid_to: String,
    pub properties: HashMap<String, String>,
}

pub fn create_relationship_object(
    db: &SekaiDb,
    spec: RelationshipObjectSpec,
) -> Result<Object, String> {
    if spec.source_id.trim().is_empty() {
        return Err("source_id required".into());
    }
    if spec.target_id.trim().is_empty() {
        return Err("target_id required".into());
    }
    if spec.relation.trim().is_empty() {
        return Err("relation required".into());
    }
    let now = chrono::Utc::now().timestamp_millis();
    let id = if spec.id.trim().is_empty() {
        format!("relationship-{}", uuid::Uuid::new_v4().simple())
    } else {
        spec.id
    };
    let source_link_id = format!("{id}:source");
    let target_link_id = format!("{id}:target");
    let mut properties = spec.properties;
    properties.insert(PROP_SOURCE_ID.into(), spec.source_id.clone());
    properties.insert(PROP_TARGET_ID.into(), spec.target_id.clone());
    properties.insert(PROP_RELATION.into(), spec.relation.clone());
    insert_non_empty(&mut properties, PROP_STATUS, spec.status);
    insert_non_empty(&mut properties, PROP_ROLE, spec.role);
    if let Some(confidence) = spec.confidence {
        if !confidence.is_finite() {
            return Err("confidence must be finite".into());
        }
        properties.insert(PROP_CONFIDENCE.into(), confidence.to_string());
    }
    insert_non_empty(&mut properties, PROP_VALID_FROM, spec.valid_from);
    insert_non_empty(&mut properties, PROP_VALID_TO, spec.valid_to);

    let relationship = Object {
        id: id.clone(),
        kind: KIND_RELATIONSHIP.into(),
        name: spec.relation.clone(),
        namespace: String::new(),
        external_id: format!("relationship:{id}"),
        properties,
        created: now,
        updated: now,
    };
    let source_id = relationship.properties[PROP_SOURCE_ID].clone();
    let target_id = relationship.properties[PROP_TARGET_ID].clone();
    let props =
        serde_json::to_string(&relationship.properties).map_err(|error| error.to_string())?;
    let mut conn = db.conn();
    let tx = conn.transaction().map_err(|error| error.to_string())?;
    if object_exists(&tx, &relationship.id)? {
        return Err("relationship object already exists".into());
    }
    if !object_exists(&tx, &source_id)? {
        return Err("source object not found".into());
    }
    if !object_exists(&tx, &target_id)? {
        return Err("target object not found".into());
    }
    if link_exists(&tx, &source_link_id)? {
        return Err("relationship source link already exists".into());
    }
    if link_exists(&tx, &target_link_id)? {
        return Err("relationship target link already exists".into());
    }
    tx.execute(
        "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            relationship.id,
            relationship.kind,
            relationship.name,
            relationship.namespace,
            relationship.external_id,
            props,
            relationship.created,
            relationship.updated
        ],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_links (id, from_id, to_id, relation, created)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            source_link_id,
            relationship.id,
            source_id,
            REL_RELATION_SOURCE,
            now
        ],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_links (id, from_id, to_id, relation, created)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            target_link_id,
            relationship.id,
            target_id,
            REL_RELATION_TARGET,
            now
        ],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(relationship)
}

pub fn relationship_objects_for_endpoint(
    db: &SekaiDb,
    endpoint_id: &str,
    role: EndpointRole,
    relation: Option<&str>,
) -> Result<Vec<Object>, String> {
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    if matches!(role, EndpointRole::Source | EndpointRole::Either) {
        collect_endpoint_relationships(
            db,
            endpoint_id,
            REL_RELATION_SOURCE,
            relation,
            &mut seen,
            &mut objects,
        )?;
    }
    if matches!(role, EndpointRole::Target | EndpointRole::Either) {
        collect_endpoint_relationships(
            db,
            endpoint_id,
            REL_RELATION_TARGET,
            relation,
            &mut seen,
            &mut objects,
        )?;
    }
    Ok(objects)
}

pub fn relationship_endpoints(
    db: &SekaiDb,
    relationship_id: &str,
) -> Result<(String, String), String> {
    let source = relationship_endpoint(db, relationship_id, REL_RELATION_SOURCE)?
        .ok_or_else(|| "relationship source endpoint not found".to_string())?;
    let target = relationship_endpoint(db, relationship_id, REL_RELATION_TARGET)?
        .ok_or_else(|| "relationship target endpoint not found".to_string())?;
    Ok((source, target))
}

fn collect_endpoint_relationships(
    db: &SekaiDb,
    endpoint_id: &str,
    endpoint_relation: &str,
    relation: Option<&str>,
    seen: &mut HashSet<String>,
    objects: &mut Vec<Object>,
) -> Result<(), String> {
    for object in db.get_linked_objects(endpoint_id, endpoint_relation, &Direction::Incoming)? {
        if object.kind != KIND_RELATIONSHIP || !seen.insert(object.id.clone()) {
            continue;
        }
        if relation
            .filter(|relation| !relation.is_empty())
            .is_some_and(|relation| {
                object
                    .properties
                    .get(PROP_RELATION)
                    .map(|value| value != relation)
                    .unwrap_or(true)
            })
        {
            continue;
        }
        objects.push(object);
    }
    Ok(())
}

fn relationship_endpoint(
    db: &SekaiDb,
    relationship_id: &str,
    endpoint_relation: &str,
) -> Result<Option<String>, String> {
    Ok(db
        .get_links(relationship_id, endpoint_relation, &Direction::Outgoing)?
        .into_iter()
        .map(|link| link.to_id)
        .next())
}

fn insert_non_empty(properties: &mut HashMap<String, String>, key: &str, value: String) {
    if !value.is_empty() {
        properties.insert(key.into(), value);
    }
}

fn object_exists(conn: &rusqlite::Connection, id: &str) -> Result<bool, String> {
    conn.query_row(
        "SELECT 1 FROM sekai_objects WHERE id = ?1",
        params![id],
        |_| Ok(()),
    )
    .optional()
    .map(|result| result.is_some())
    .map_err(|error| error.to_string())
}

fn link_exists(conn: &rusqlite::Connection, id: &str) -> Result<bool, String> {
    conn.query_row(
        "SELECT 1 FROM sekai_links WHERE id = ?1",
        params![id],
        |_| Ok(()),
    )
    .optional()
    .map(|result| result.is_some())
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Link, REL_CONTAINS, REL_TOUCHES};

    fn object(id: &str, kind: &str) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: String::new(),
            external_id: format!("{kind}:{id}"),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn relationship_object_helpers_create_and_query_metadata_object() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&object("source", "component")).unwrap();
        db.create_object(&object("target", "model")).unwrap();

        let relationship = create_relationship_object(
            &db,
            RelationshipObjectSpec {
                id: "rel-1".into(),
                relation: REL_TOUCHES.into(),
                source_id: "source".into(),
                target_id: "target".into(),
                status: "active".into(),
                role: "producer".into(),
                confidence: Some(0.81),
                valid_from: "2026-07-06T12:00:00Z".into(),
                valid_to: String::new(),
                properties: HashMap::from([("note".into(), "observed by evaluator".into())]),
            },
        )
        .unwrap();

        assert_eq!(relationship.kind, KIND_RELATIONSHIP);
        assert_eq!(relationship.properties[PROP_SOURCE_ID], "source");
        assert_eq!(relationship.properties[PROP_TARGET_ID], "target");
        assert_eq!(relationship.properties[PROP_RELATION], REL_TOUCHES);
        assert_eq!(relationship.properties[PROP_STATUS], "active");
        assert_eq!(relationship.properties[PROP_ROLE], "producer");
        assert_eq!(relationship.properties[PROP_CONFIDENCE], "0.81");
        assert_eq!(
            relationship.properties[PROP_VALID_FROM],
            "2026-07-06T12:00:00Z"
        );

        let source_relationships = relationship_objects_for_endpoint(
            &db,
            "source",
            EndpointRole::Source,
            Some(REL_TOUCHES),
        )
        .unwrap();
        assert_eq!(source_relationships.len(), 1);
        assert_eq!(source_relationships[0].id, "rel-1");
        assert!(
            relationship_objects_for_endpoint(
                &db,
                "source",
                EndpointRole::Source,
                Some(REL_CONTAINS),
            )
            .unwrap()
            .is_empty()
        );

        let target_relationships =
            relationship_objects_for_endpoint(&db, "target", EndpointRole::Target, None).unwrap();
        assert_eq!(target_relationships.len(), 1);
        assert_eq!(
            relationship_endpoints(&db, "rel-1").unwrap(),
            ("source".into(), "target".into())
        );
    }

    #[test]
    fn relationship_objects_do_not_change_existing_bare_link_queries() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&object("source", "component")).unwrap();
        db.create_object(&object("target", "model")).unwrap();
        db.create_link(&Link {
            id: "bare".into(),
            from_id: "source".into(),
            to_id: "target".into(),
            relation: REL_CONTAINS.into(),
            created: 1,
        })
        .unwrap();
        create_relationship_object(
            &db,
            RelationshipObjectSpec {
                id: "rel-1".into(),
                relation: REL_TOUCHES.into(),
                source_id: "source".into(),
                target_id: "target".into(),
                status: String::new(),
                role: String::new(),
                confidence: None,
                valid_from: String::new(),
                valid_to: String::new(),
                properties: HashMap::new(),
            },
        )
        .unwrap();

        let bare_links = db
            .get_links("source", REL_CONTAINS, &Direction::Outgoing)
            .unwrap();
        assert_eq!(bare_links.len(), 1);
        assert_eq!(bare_links[0].id, "bare");
        let contains_objects = db
            .get_linked_objects("source", REL_CONTAINS, &Direction::Outgoing)
            .unwrap();
        assert_eq!(contains_objects.len(), 1);
        assert_eq!(contains_objects[0].id, "target");
    }

    #[test]
    fn relationship_object_creation_rejects_derived_endpoint_link_collisions() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&object("source", "component")).unwrap();
        db.create_object(&object("target", "model")).unwrap();
        db.create_link(&Link {
            id: "rel-1:source".into(),
            from_id: "source".into(),
            to_id: "target".into(),
            relation: REL_CONTAINS.into(),
            created: 1,
        })
        .unwrap();

        let err = create_relationship_object(
            &db,
            RelationshipObjectSpec {
                id: "rel-1".into(),
                relation: REL_TOUCHES.into(),
                source_id: "source".into(),
                target_id: "target".into(),
                status: String::new(),
                role: String::new(),
                confidence: None,
                valid_from: String::new(),
                valid_to: String::new(),
                properties: HashMap::new(),
            },
        )
        .unwrap_err();

        assert!(err.contains("source link already exists"));
        assert!(db.get_object("rel-1").unwrap().is_none());
        assert!(
            relationship_objects_for_endpoint(&db, "source", EndpointRole::Source, None)
                .unwrap()
                .is_empty()
        );
    }
}
