use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Barrier};

use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{Direction, KIND_CAPABILITY, Link, ListFilter, Object, PropertyFilter};
use sekai_chisei::sekai::classification_lattice::{
    CLASSIFICATION_LATTICE_VERSION, ClassificationLattice,
};
use sekai_chisei::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
    ObjectSecurityPredicate, ObjectSecurityRule, PrincipalPolicyContext, PropertyGrant,
    PropertyGrantAccess, object_security_activation_digest,
};
use sekai_chisei::sekai::purpose_authorization::{
    PURPOSE_AUTHORIZATION_VERSION, PurposeAuthorization,
};
use sekai_chisei::sekai::query::{self, GraphQuery};

fn policy(
    namespace: &str,
    kind: &str,
    predicates: Vec<ObjectSecurityPredicate>,
) -> ObjectSecurityPolicy {
    ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: kind.into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates,
        }],
        property_grants: None,
        required_purpose: None,
    }
}

fn object_id(namespace: &str, id: &str) -> String {
    format!("{namespace}:{id}")
}

fn object(namespace: &str, id: &str, name: &str, owner: &str, state: &str) -> Object {
    Object {
        id: object_id(namespace, id),
        kind: "document".into(),
        name: name.into(),
        namespace: namespace.into(),
        external_id: object_id(namespace, id),
        properties: HashMap::from([
            ("owner".into(), owner.into()),
            ("state".into(), state.into()),
        ]),
        created: 1,
        updated: 1,
    }
}

fn exercise(db: RuntimeDb, namespace: &str) {
    for candidate in [
        object(namespace, "a", "alpha", "alice", "open"),
        object(namespace, "b", "bravo", "bob", "open"),
        object(namespace, "c", "charlie", "alice", "closed"),
        object(namespace, "d", "delta", "alice", "open"),
    ] {
        db.create_object(&candidate).unwrap();
    }
    let mut missing_owner = object(namespace, "e", "echo", "ignored", "open");
    missing_owner.properties.remove("owner");
    db.create_object(&missing_owner).unwrap();

    let broad = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::AllowAll],
    );
    let broad_revision = db
        .put_object_security_policy(&broad, "root", "put-broad", 1)
        .unwrap();
    assert_eq!(
        db.put_object_security_policy(&broad, "root", "put-broad", 2)
            .unwrap(),
        broad_revision
    );
    let conflicting = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::PropertyEquals {
            property: "state".into(),
            value: "open".into(),
        }],
    );
    assert!(
        db.put_object_security_policy(&conflicting, "root", "put-broad", 3)
            .unwrap_err()
            .contains("idempotency_conflict")
    );

    let broad_map = BTreeMap::from([(
        "document".to_string(),
        broad_revision.revision_digest.clone(),
    )]);
    let broad_activation = db
        .activate_object_security_policies(namespace, &broad_map, "root", "activate-broad", 4)
        .unwrap();
    assert_eq!(
        db.activate_object_security_policies(namespace, &broad_map, "root", "activate-broad", 5)
            .unwrap(),
        broad_activation
    );
    assert_eq!(
        db.get_object_security_policy(namespace, &broad_revision.revision_digest)
            .unwrap()
            .unwrap(),
        broad_revision
    );
    assert_eq!(
        db.get_object_security_activation(namespace)
            .unwrap()
            .unwrap(),
        broad_activation
    );
    let empty = PrincipalPolicyContext::default();
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "b"), &empty)
            .unwrap()
            .is_some()
    );

    let owner = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::SubjectEqualsProperty {
            property: "owner".into(),
        }],
    );
    let owner_revision = db
        .put_object_security_policy(&owner, "root", "put-owner", 6)
        .unwrap();
    assert!(
        db.activate_object_security_policies(
            namespace,
            &BTreeMap::from([("document".into(), owner_revision.revision_digest.clone())]),
            "root",
            "activate-broad",
            7,
        )
        .unwrap_err()
        .contains("idempotency_conflict")
    );
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), owner_revision.revision_digest.clone())]),
        "root",
        "activate-owner",
        8,
    )
    .unwrap();
    let alice = PrincipalPolicyContext {
        subjects: vec!["alice".into()],
        scopes: vec![],
    };
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "a"), &alice)
            .unwrap()
            .is_some()
    );
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "b"), &alice)
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "e"), &alice)
            .unwrap()
            .is_none()
    );

    let filter = ListFilter {
        namespace: Some(namespace.into()),
        kind: Some("document".into()),
        property_filters: vec![PropertyFilter {
            key: "state".into(),
            op: "eq".into(),
            value: "open".into(),
        }],
        order_by: "name".into(),
        offset: 1,
        limit: 1,
        ..Default::default()
    };
    let (rows, total) = db
        .list_objects_with_total_for_policy_context(&filter, &["alice"], &[], &alice)
        .unwrap();
    assert_eq!(total, 2);
    assert_eq!(
        rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
        vec![object_id(namespace, "d")]
    );

    let scoped = policy(
        namespace,
        "document",
        vec![
            ObjectSecurityPredicate::RequiredScopeEquals {
                value: "documents:read".into(),
            },
            ObjectSecurityPredicate::PropertyEquals {
                property: "state".into(),
                value: "open".into(),
            },
        ],
    );
    let scoped_revision = db
        .put_object_security_policy(&scoped, "root", "put-scoped", 9)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), scoped_revision.revision_digest)]),
        "root",
        "activate-scoped",
        10,
    )
    .unwrap();
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "a"), &empty)
            .unwrap()
            .is_none()
    );
    let authorized_scope = PrincipalPolicyContext {
        subjects: vec!["nobody".into()],
        scopes: vec!["documents:read".into()],
    };
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "a"), &authorized_scope)
            .unwrap()
            .is_some()
    );
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "c"), &authorized_scope)
            .unwrap()
            .is_none()
    );

    let write = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "document".into(),
        property_grants: None,
        rules: vec![
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Update,
                predicates: vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                    property: "owner".into(),
                }],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Delete,
                predicates: vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                    property: "owner".into(),
                }],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Create,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Sync,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            },
        ],
        required_purpose: None,
    };
    let write_revision = db
        .put_object_security_policy(&write, "root", "put-write", 11)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), write_revision.revision_digest.clone())]),
        "root",
        "activate-write",
        12,
    )
    .unwrap();
    let loaded = db
        .active_object_policy(namespace, "document")
        .unwrap()
        .unwrap();
    let alice = PrincipalPolicyContext {
        subjects: vec!["alice".into()],
        scopes: Vec::new(),
    };
    let bob = PrincipalPolicyContext {
        subjects: vec!["bob".into()],
        scopes: Vec::new(),
    };
    let alice_object = object(namespace, "a", "alpha", "alice", "open");
    assert!(loaded.allows(&alice, &alice_object, ObjectSecurityOperation::Read));
    assert!(loaded.allows(&alice, &alice_object, ObjectSecurityOperation::Update));
    assert!(!loaded.allows(&bob, &alice_object, ObjectSecurityOperation::Update));
    assert_eq!(db.object_query_cursor_key().unwrap().len(), 32);
    assert_eq!(
        db.object_query_cursor_key().unwrap(),
        db.object_query_cursor_key().unwrap()
    );

    let mut secret_object = object(namespace, "grant-secret", "grant-secret", "alice", "open");
    secret_object
        .properties
        .insert("secret".into(), "classified".into());
    db.create_object(&secret_object).unwrap();
    let grants = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "document".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: Some(vec![
            PropertyGrant {
                property: "owner".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "state".into(),
                access: PropertyGrantAccess::Read,
            },
        ]),
        required_purpose: None,
    };
    let grant_revision = db
        .put_object_security_policy(&grants, "root", "put-grants", 13)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), grant_revision.revision_digest)]),
        "root",
        "activate-grants",
        14,
    )
    .unwrap();
    let projected = db
        .project_object_property_grants(
            db.get_object_with_policy_context(&object_id(namespace, "grant-secret"), &alice)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    assert!(!projected.properties.contains_key("secret"));
    assert!(
        db.list_objects_with_total_for_policy_context(
            &ListFilter {
                namespace: Some(namespace.into()),
                kind: Some("document".into()),
                property_filters: vec![PropertyFilter {
                    key: "secret".into(),
                    op: "eq".into(),
                    value: "classified".into(),
                }],
                limit: 10,
                ..Default::default()
            },
            &["alice"],
            &[],
            &alice,
        )
        .unwrap_err()
        .contains("object_security_denied")
    );
}

fn exercise_row_scoped_query_paths(db: &RuntimeDb, namespace: &str) {
    let alice_open = object(namespace, "alice-open", "alice-open", "alice", "open");
    let bob_open = object(namespace, "bob-open", "bob-open", "bob", "open");
    let alice_closed = object(namespace, "alice-closed", "alice-closed", "alice", "closed");
    let alice_leaf = object(namespace, "alice-leaf", "alice-leaf", "alice", "open");
    for candidate in [
        alice_open.clone(),
        bob_open.clone(),
        alice_closed.clone(),
        alice_leaf.clone(),
    ] {
        db.create_object(&candidate).unwrap();
    }
    db.create_link(&Link {
        id: format!("{namespace}:alice-to-bob"),
        from_id: alice_open.id.clone(),
        to_id: bob_open.id.clone(),
        relation: "contains".into(),
        created: 1,
    })
    .unwrap();
    db.create_link(&Link {
        id: format!("{namespace}:bob-to-leaf"),
        from_id: bob_open.id.clone(),
        to_id: alice_leaf.id.clone(),
        relation: "contains".into(),
        created: 1,
    })
    .unwrap();
    db.create_link(&Link {
        id: format!("{namespace}:alice-to-closed"),
        from_id: alice_open.id.clone(),
        to_id: alice_closed.id.clone(),
        relation: "contains".into(),
        created: 1,
    })
    .unwrap();

    let owner = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::SubjectEqualsProperty {
            property: "owner".into(),
        }],
    );
    let revision = db
        .put_object_security_policy(&owner, "root", "put-row-scope", 1)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), revision.revision_digest)]),
        "root",
        "activate-row-scope",
        2,
    )
    .unwrap();

    let alice = PrincipalPolicyContext {
        subjects: vec!["alice".into()],
        scopes: vec![],
    };
    let mut authorized = db
        .find_by_property_with_policy_context("document", "state", "open", &alice)
        .unwrap()
        .into_iter()
        .filter(|row| row.namespace == namespace)
        .collect::<Vec<_>>();
    authorized.sort_by(|left, right| left.id.cmp(&right.id));
    let authorized_ids = authorized
        .iter()
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        authorized_ids,
        vec![alice_leaf.id.clone(), alice_open.id.clone()]
    );
    let (listed, total) = db
        .list_objects_with_total_for_policy_context(
            &ListFilter {
                namespace: Some(namespace.into()),
                kind: Some("document".into()),
                property_filters: vec![PropertyFilter {
                    key: "state".into(),
                    op: "eq".into(),
                    value: "open".into(),
                }],
                limit: 10,
                ..Default::default()
            },
            &["alice"],
            &[],
            &alice,
        )
        .unwrap();
    assert_eq!(total, authorized.len() as i32);
    assert_eq!(
        listed.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
        authorized_ids
    );

    assert!(
        db.find_all_by_external_id_with_policy_context(&bob_open.external_id, &alice)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.find_all_by_external_id_with_policy_context(&alice_open.external_id, &alice)
            .unwrap()
            .iter()
            .map(|row| row.id.clone())
            .collect::<Vec<_>>(),
        vec![alice_open.id.clone()]
    );
    assert!(
        db.get_object_with_policy_context(&bob_open.id, &alice)
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_object_with_policy_context(&format!("{namespace}:absent"), &alice)
            .unwrap()
            .is_none()
    );

    let neighbors = db
        .get_linked_objects_with_policy_context(
            &alice_open.id,
            "contains",
            &Direction::Outgoing,
            &alice,
        )
        .unwrap();
    assert_eq!(
        neighbors
            .iter()
            .map(|row| row.id.clone())
            .collect::<Vec<_>>(),
        vec![alice_closed.id.clone()]
    );
    let links = db
        .get_links_with_policy_context(&alice_open.id, "contains", &Direction::Outgoing, &alice)
        .unwrap();
    assert_eq!(
        links
            .iter()
            .map(|link| link.to_id.clone())
            .collect::<Vec<_>>(),
        vec![alice_closed.id.clone()]
    );

    let traversed = query::traverse_with_policy_context(
        db,
        &GraphQuery {
            start_id: alice_open.id.clone(),
            relations: vec!["contains".into()],
            direction: Direction::Outgoing,
            max_depth: 3,
            ..Default::default()
        },
        None,
        Some(&alice),
        None,
    )
    .unwrap();
    let traversed_ids = traversed
        .objects
        .iter()
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    assert!(traversed_ids.contains(&alice_closed.id));
    assert!(!traversed_ids.contains(&bob_open.id));
    assert!(
        !traversed_ids.contains(&alice_leaf.id),
        "hidden hops must not expand a visible descendant"
    );

    let lineage = db
        .get_lineage_with_policy_context(&alice_open.id, 20, &alice)
        .unwrap();
    let lineage_ids = lineage
        .nodes
        .iter()
        .map(|node| node.object.id.clone())
        .collect::<Vec<_>>();
    assert!(lineage_ids.contains(&alice_open.id));
    assert!(lineage_ids.contains(&alice_closed.id));
    assert!(!lineage_ids.contains(&bob_open.id));
    assert!(!lineage_ids.contains(&alice_leaf.id));
}

fn exercise_property_level_reads(db: &RuntimeDb, namespace: &str) {
    let mut classified = object(namespace, "visible-a", "visible-a", "alice", "open");
    classified
        .properties
        .insert("note".into(), "visible".into());
    classified
        .properties
        .insert("secret".into(), "classified".into());
    let mut twin = object(namespace, "visible-b", "visible-b", "alice", "open");
    twin.properties.insert("note".into(), "visible".into());
    twin.properties.insert("secret".into(), "other".into());
    db.create_object(&classified).unwrap();
    db.create_object(&twin).unwrap();
    db.create_link(&Link {
        id: format!("{namespace}:a-to-b"),
        from_id: classified.id.clone(),
        to_id: twin.id.clone(),
        relation: "contains".into(),
        created: 1,
    })
    .unwrap();

    let grants = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "document".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: Some(vec![
            PropertyGrant {
                property: "owner".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "state".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "note".into(),
                access: PropertyGrantAccess::Read,
            },
        ]),
        required_purpose: None,
    };
    let revision = db
        .put_object_security_policy(&grants, "root", "put-column-reads", 1)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), revision.revision_digest)]),
        "root",
        "activate-column-reads",
        2,
    )
    .unwrap();

    let alice = PrincipalPolicyContext {
        subjects: vec!["alice".into()],
        scopes: vec![],
    };
    let hidden_filter = db
        .find_by_property_with_policy_context("document", "secret", "classified", &alice)
        .unwrap_err();
    let unknown_filter = db
        .find_by_property_with_policy_context("document", "unknown", "missing", &alice)
        .unwrap_err();
    assert!(hidden_filter.contains("object_security_denied"));
    assert_eq!(hidden_filter, unknown_filter);
    assert!(
        query::traverse_with_policy_context(
            db,
            &GraphQuery {
                start_id: classified.id.clone(),
                relations: vec!["contains".into()],
                direction: Direction::Outgoing,
                max_depth: 1,
                property_filter: HashMap::from([("secret".into(), "classified".into())]),
                ..Default::default()
            },
            None,
            Some(&alice),
            None,
        )
        .unwrap_err()
        .contains("object_security_denied")
    );
    assert!(
        db.list_objects_with_total_for_policy_context(
            &ListFilter {
                namespace: Some(namespace.into()),
                kind: Some("document".into()),
                order_by: "property:secret".into(),
                limit: 10,
                ..Default::default()
            },
            &["alice"],
            &[],
            &alice,
        )
        .unwrap_err()
        .contains("object_security_denied")
    );

    let mut found = db
        .find_by_property_with_policy_context("document", "state", "open", &alice)
        .unwrap()
        .into_iter()
        .filter(|row| row.namespace == namespace)
        .map(|row| db.project_object_property_grants(row).unwrap())
        .collect::<Vec<_>>();
    found.sort_by(|left, right| left.id.cmp(&right.id));
    assert_eq!(
        found.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
        vec![classified.id.clone(), twin.id.clone()]
    );
    assert!(
        found
            .iter()
            .all(|row| !row.properties.contains_key("secret")
                && row.properties.get("note").map(String::as_str) == Some("visible"))
    );

    let traversed = query::traverse_with_policy_context(
        db,
        &GraphQuery {
            start_id: classified.id.clone(),
            relations: vec!["contains".into()],
            direction: Direction::Outgoing,
            max_depth: 1,
            ..Default::default()
        },
        None,
        Some(&alice),
        None,
    )
    .unwrap();
    let projected_hop = db
        .project_object_property_grants(traversed.objects[0].clone())
        .unwrap();
    assert_eq!(projected_hop.id, twin.id);
    assert!(!projected_hop.properties.contains_key("secret"));

    let lineage = db
        .get_lineage_with_policy_context(&classified.id, 20, &alice)
        .unwrap();
    assert!(
        lineage
            .nodes
            .iter()
            .map(|node| db
                .project_object_property_grants(node.object.clone())
                .unwrap())
            .all(|object| !object.properties.contains_key("secret"))
    );

    let mut revoked = grants;
    revoked.property_grants = Some(vec![
        PropertyGrant {
            property: "owner".into(),
            access: PropertyGrantAccess::Read,
        },
        PropertyGrant {
            property: "state".into(),
            access: PropertyGrantAccess::Read,
        },
    ]);
    let revoked_revision = db
        .put_object_security_policy(&revoked, "root", "put-column-revoke", 3)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), revoked_revision.revision_digest)]),
        "root",
        "activate-column-revoke",
        4,
    )
    .unwrap();
    let after_revoke = db
        .project_object_property_grants(
            db.get_object_with_policy_context(&classified.id, &alice)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    assert!(!after_revoke.properties.contains_key("note"));
    assert!(!after_revoke.properties.contains_key("secret"));
    assert_eq!(
        after_revoke.properties.get("state").map(String::as_str),
        Some("open")
    );
}

fn exercise_purpose_bound_reads(db: &RuntimeDb, namespace: &str) {
    db.create_object(&object(namespace, "doc", "doc", "alice", "open"))
        .unwrap();
    let mut purpose_policy = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::AllowAll],
    );
    purpose_policy.required_purpose = Some("incident-response".into());
    let revision = db
        .put_object_security_policy(&purpose_policy, "root", "put-purpose", 1)
        .unwrap();
    let activation = db
        .activate_object_security_policies(
            namespace,
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate-purpose",
            2,
        )
        .unwrap();
    let digest = object_security_activation_digest(&activation).unwrap();
    let live = PurposeAuthorization {
        contract_version: PURPOSE_AUTHORIZATION_VERSION.into(),
        authorization_id: format!("{namespace}-live"),
        actor: "alice".into(),
        purpose: "incident-response".into(),
        namespace: namespace.into(),
        kind: "document".into(),
        not_before_ms: 10,
        not_after_ms: 20,
        policy_activation_digest: digest.clone(),
        created_by: "root".into(),
        created_at_ms: 10,
        revoked_at_ms: 0,
    };
    match db.put_purpose_authorization(&live) {
        Ok(_) => {}
        Err(error) if error.contains("unavailable") => return,
        Err(error) => panic!("{error}"),
    }
    let mut unknown = live.clone();
    unknown.authorization_id = format!("{namespace}-v2");
    unknown.contract_version = "sekai.purpose-authorization/v2".into();
    assert!(
        db.put_purpose_authorization(&unknown)
            .unwrap_err()
            .contains("unsupported purpose authorization contract")
    );
    assert!(
        db.find_purpose_authorization(
            "alice",
            "incident-response",
            namespace,
            "document",
            &digest,
            15
        )
        .unwrap()
        .is_some()
    );
    assert!(
        db.find_purpose_authorization("alice", "analytics", namespace, "document", &digest, 15)
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_purpose_authorization(
            "alice",
            "incident-response",
            namespace,
            "document",
            &digest,
            21
        )
        .unwrap()
        .is_none()
    );
    assert!(
        db.find_purpose_authorization(
            "bob",
            "incident-response",
            namespace,
            "document",
            &digest,
            15
        )
        .unwrap()
        .is_none()
    );
    assert!(
        db.find_purpose_authorization(
            "alice",
            "incident-response",
            namespace,
            "document",
            "stale-activation",
            15
        )
        .unwrap()
        .is_none()
    );
    assert!(
        db.find_purpose_authorization(
            "alice",
            "incident-response",
            "other",
            "document",
            &digest,
            15
        )
        .unwrap()
        .is_none()
    );
    let mut revoked = live.clone();
    revoked.authorization_id = format!("{namespace}-revoked");
    revoked.revoked_at_ms = 14;
    db.put_purpose_authorization(&revoked).unwrap();
    assert!(
        db.find_purpose_authorization(
            "alice",
            "incident-response",
            namespace,
            "document",
            &digest,
            15
        )
        .unwrap()
        .is_some_and(|found| found.authorization_id == live.authorization_id)
    );
    db.revoke_purpose_authorization(&live.authorization_id, 16)
        .unwrap();
    assert!(
        db.find_purpose_authorization(
            "alice",
            "incident-response",
            namespace,
            "document",
            &digest,
            15
        )
        .unwrap()
        .is_none()
    );
}

fn exercise_classification_lattices(db: &RuntimeDb, namespace: &str) {
    let lattice = ClassificationLattice {
        contract_version: CLASSIFICATION_LATTICE_VERSION.into(),
        namespace: namespace.into(),
        tokens: vec![
            "public".into(),
            "internal".into(),
            "confidential".into(),
            "secret".into(),
            "health".into(),
        ],
        parents: BTreeMap::from([
            ("public".into(), vec!["internal".into()]),
            ("internal".into(), vec!["confidential".into()]),
            ("confidential".into(), vec!["secret".into()]),
            ("health".into(), vec!["secret".into()]),
        ]),
        incomparable: vec![("confidential".into(), "health".into())],
    };
    match db.put_classification_lattice(&lattice, "root", 10) {
        Ok(stored) => {
            assert_eq!(stored.namespace, namespace);
            let loaded = db.get_classification_lattice(namespace).unwrap().unwrap();
            assert_eq!(loaded.digest().unwrap(), stored.digest().unwrap());
            assert!(loaded.dominates("secret", "health").unwrap());
            assert_eq!(loaded.join("confidential", "health").unwrap(), None);
            let mut unknown = stored.clone();
            unknown.contract_version = "sekai.classification-lattice/v2".into();
            assert!(
                db.put_classification_lattice(&unknown, "root", 11)
                    .unwrap_err()
                    .contains("unsupported classification lattice contract")
            );
        }
        Err(error) if error.contains("unavailable") => {
            assert!(db.get_classification_lattice(namespace).unwrap().is_none());
        }
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn sqlite_object_security_conformance() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    exercise(db.clone(), "object-security-sqlite");
    exercise_row_scoped_query_paths(&db, "row-scope-sqlite");
    exercise_property_level_reads(&db, "column-reads-sqlite");
    exercise_purpose_bound_reads(&db, "purpose-sqlite");
    exercise_classification_lattices(&db, "lattice-sqlite");
}

#[test]
fn sqlite_activation_requires_every_instantiated_kind() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object("incomplete", "doc", "doc", "alice", "open"))
        .unwrap();
    let mut other = object("incomplete", "other", "other", "alice", "open");
    other.kind = "other".into();
    db.create_object(&other).unwrap();
    let revision = db
        .put_object_security_policy(
            &policy(
                "incomplete",
                "document",
                vec![ObjectSecurityPredicate::AllowAll],
            ),
            "root",
            "put",
            1,
        )
        .unwrap();
    assert!(
        db.activate_object_security_policies(
            "incomplete",
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate",
            2,
        )
        .unwrap_err()
        .contains("activation_incomplete")
    );
}

#[test]
fn sqlite_unactivated_namespace_keeps_broad_unfiltered_listing() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object(
        "activated",
        "activated-doc",
        "activated",
        "alice",
        "open",
    ))
    .unwrap();
    db.create_object(&object("legacy", "legacy-doc", "legacy", "alice", "open"))
        .unwrap();
    let revision = db
        .put_object_security_policy(
            &policy(
                "activated",
                "document",
                vec![ObjectSecurityPredicate::AllowAll],
            ),
            "root",
            "put-activated",
            1,
        )
        .unwrap();
    db.activate_object_security_policies(
        "activated",
        &BTreeMap::from([("document".into(), revision.revision_digest)]),
        "root",
        "activate",
        2,
    )
    .unwrap();

    let (rows, total) = db
        .list_objects_with_total_for_policy_context(
            &ListFilter {
                limit: 100,
                ..Default::default()
            },
            &["alice"],
            &[],
            &PrincipalPolicyContext {
                subjects: vec!["alice".into()],
                scopes: vec![],
            },
        )
        .unwrap();
    assert_eq!(total, 2);
    assert!(
        rows.iter()
            .any(|row| row.id == object_id("legacy", "legacy-doc"))
    );
}

#[test]
fn sqlite_policy_lists_exclude_reserved_kinds() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object("ns", "doc", "doc", "alice", "open"))
        .unwrap();
    let mut reserved = object("ns", "cap", "cap", "alice", "open");
    reserved.kind = KIND_CAPABILITY.into();
    db.create_object(&reserved).unwrap();
    let (rows, total) = db
        .list_objects_with_total_for_policy_context(
            &ListFilter {
                namespace: Some("ns".into()),
                limit: 100,
                ..Default::default()
            },
            &["alice"],
            &[KIND_CAPABILITY],
            &PrincipalPolicyContext::default(),
        )
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(
        rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
        vec![object_id("ns", "doc")]
    );
}

#[test]
fn sqlite_rejects_nul_object_properties() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    let mut poisoned = object("ns", "poison", "poison", "alice", "open");
    poisoned.properties.insert("owner".into(), "alice\0".into());
    assert!(db.create_object(&poisoned).unwrap_err().contains("NUL"));

    let mut stored = object("ns", "ok", "ok", "alice", "open");
    db.create_object(&stored).unwrap();
    stored.updated = 2;
    stored.properties.insert("owner".into(), "alice\0".into());
    assert!(db.update_object(&stored).unwrap_err().contains("NUL"));
}

#[test]
fn sqlite_activation_audit_stores_mapping_digest() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object("audit", "doc", "doc", "alice", "open"))
        .unwrap();
    let revision = db
        .put_object_security_policy(
            &policy("audit", "document", vec![ObjectSecurityPredicate::AllowAll]),
            "root",
            "put-audit",
            1,
        )
        .unwrap();
    let activation = db
        .activate_object_security_policies(
            "audit",
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate-audit",
            2,
        )
        .unwrap();
    let digest: String = db
        .conn()
        .query_row(
            "SELECT revision_digest FROM sekai_object_security_audit
             WHERE action='activate' AND namespace=?1",
            ["audit"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(digest, activation.activation_id);
}

#[test]
fn sqlite_property_grants_omit_hidden_values_and_deny_ungranted_filters() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    let namespace = "grants";
    let mut stored = object(namespace, "a", "alpha", "alice", "open");
    stored
        .properties
        .insert("secret".into(), "classified".into());
    db.create_object(&stored).unwrap();

    let policy = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "document".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: Some(vec![
            PropertyGrant {
                property: "owner".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "owner".into(),
                access: PropertyGrantAccess::Write,
            },
            PropertyGrant {
                property: "state".into(),
                access: PropertyGrantAccess::Read,
            },
        ]),
        required_purpose: None,
    };
    let revision = db
        .put_object_security_policy(&policy, "root", "put-grants", 1)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), revision.revision_digest)]),
        "root",
        "activate-grants",
        2,
    )
    .unwrap();

    let alice = PrincipalPolicyContext {
        subjects: vec!["alice".into()],
        scopes: vec![],
    };
    let loaded = db
        .project_object_property_grants(
            db.get_object_with_policy_context(&object_id(namespace, "a"), &alice)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        loaded.properties.get("owner").map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        loaded.properties.get("state").map(String::as_str),
        Some("open")
    );
    assert!(!loaded.properties.contains_key("secret"));
    let raw = db.get_object(&object_id(namespace, "a")).unwrap().unwrap();
    assert_eq!(
        raw.properties.get("secret").map(String::as_str),
        Some("classified")
    );

    let (rows, total) = db
        .list_objects_with_total_for_policy_context(
            &ListFilter {
                namespace: Some(namespace.into()),
                kind: Some("document".into()),
                property_filters: vec![PropertyFilter {
                    key: "state".into(),
                    op: "eq".into(),
                    value: "open".into(),
                }],
                limit: 10,
                ..Default::default()
            },
            &["alice"],
            &[],
            &alice,
        )
        .unwrap();
    assert_eq!(total, 1);
    assert!(rows[0].properties.contains_key("secret"));
    assert!(
        !db.project_object_property_grants(rows[0].clone())
            .unwrap()
            .properties
            .contains_key("secret")
    );

    assert!(
        db.list_objects_with_total_for_policy_context(
            &ListFilter {
                namespace: Some(namespace.into()),
                kind: Some("document".into()),
                property_filters: vec![PropertyFilter {
                    key: "secret".into(),
                    op: "eq".into(),
                    value: "classified".into(),
                }],
                limit: 10,
                ..Default::default()
            },
            &["alice"],
            &[],
            &alice,
        )
        .unwrap_err()
        .contains("object_security_denied")
    );
    assert!(
        db.list_objects_with_total_for_policy_context(
            &ListFilter {
                property_filters: vec![PropertyFilter {
                    key: "secret".into(),
                    op: "eq".into(),
                    value: "classified".into(),
                }],
                limit: 10,
                ..Default::default()
            },
            &["alice"],
            &[],
            &alice,
        )
        .unwrap_err()
        .contains("object_security_denied")
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_object_security_conformance() {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let postgres = Arc::new(PostgresDb::connect(&url, 4).unwrap());
    let db = RuntimeDb::Postgres(postgres.clone());
    exercise(
        db.clone(),
        &format!("object-security-{}", uuid::Uuid::new_v4().simple()),
    );
    exercise_row_scoped_query_paths(&db, &format!("row-scope-{}", uuid::Uuid::new_v4().simple()));
    exercise_property_level_reads(
        &db,
        &format!("column-reads-{}", uuid::Uuid::new_v4().simple()),
    );
    exercise_purpose_bound_reads(&db, &format!("purpose-{}", uuid::Uuid::new_v4().simple()));
    exercise_classification_lattices(&db, &format!("lattice-{}", uuid::Uuid::new_v4().simple()));

    let namespace = format!("object-security-put-race-{}", uuid::Uuid::new_v4().simple());
    let policy = Arc::new(policy(
        &namespace,
        "document",
        vec![ObjectSecurityPredicate::AllowAll],
    ));
    let barrier = Arc::new(Barrier::new(2));
    let results = (0..2)
        .map(|index| {
            let postgres = postgres.clone();
            let policy = policy.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                postgres.put_object_security_policy(
                    &policy,
                    "root",
                    &format!("concurrent-put-{index}"),
                    42,
                )
            })
        })
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results[0], results[1]);
}
