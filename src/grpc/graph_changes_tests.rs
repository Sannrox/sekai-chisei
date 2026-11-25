//! `ApplyGraphChanges` through the service: revisions, patch scope, in-call
//! links, replay, and authorization equal to the single-record RPCs (#3062).
//! Store atomicity, fencing and Action instance binding are covered on both
//! backends in `tests/graph_changes_backend_conformance.rs`.

use super::*;
use tonic::metadata::MetadataValue;

fn service() -> SekaiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    crate::chisei_store::apply_chisei_schema(&db);
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
}

fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    req
}

fn seed(svc: &SekaiServiceImpl, id: &str, properties: &[(&str, &str)]) {
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: id.into(),
            kind: "task".into(),
            name: id.into(),
            namespace: "ops".into(),
            external_id: String::new(),
            properties: properties
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            created: 1,
            updated: 1,
        })
        .unwrap();
}

async fn revision(svc: &SekaiServiceImpl, id: &str, principal: &str) -> String {
    let object = svc
        .get_visible_object(as_principal(GetObjectRequest { id: id.into() }, principal))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap();
    assert!(!object.revision.is_empty());
    object.revision
}

fn patch(id: &str, expected_revision: &str, set: &[(&str, &str)], remove: &[&str]) -> GraphChange {
    GraphChange {
        change: Some(graph_change::Change::PatchObject(GraphObjectPatch {
            object_id: id.into(),
            expected_revision: expected_revision.into(),
            set_properties: set
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            remove_properties: remove.iter().map(|key| key.to_string()).collect(),
        })),
    }
}

fn create(id: &str) -> GraphChange {
    GraphChange {
        change: Some(graph_change::Change::CreateObject(Object {
            id: id.into(),
            kind: "task".into(),
            name: id.into(),
            ..Default::default()
        })),
    }
}

fn request(request_id: &str, changes: Vec<GraphChange>) -> ApplyGraphChangesRequest {
    ApplyGraphChangesRequest {
        namespace: "ops".into(),
        request_id: request_id.into(),
        changes,
        action_instance_id: String::new(),
    }
}

#[tokio::test]
async fn patches_named_properties_links_new_objects_and_replays() {
    let svc = service();
    seed(
        &svc,
        "t1",
        &[("state", "open"), ("owner", "ann"), ("note", "x")],
    );
    let before = revision(&svc, "t1", "tester").await;
    let changes = vec![
        create("t2"),
        patch("t1", &before, &[("state", "planned")], &["note"]),
        GraphChange {
            change: Some(graph_change::Change::CreateLink(Link {
                id: "t1-blocks-t2".into(),
                from_id: "t1".into(),
                to_id: "t2".into(),
                relation: "blocks".into(),
                created: 0,
            })),
        },
    ];
    let applied = svc
        .apply_graph_changes_rpc(as_principal(request("r1", changes.clone()), "tester"))
        .await
        .unwrap()
        .into_inner();
    assert!(!applied.replayed);
    assert_eq!(
        applied
            .objects
            .iter()
            .map(|o| o.id.as_str())
            .collect::<Vec<_>>(),
        ["t2", "t1"]
    );
    let t1 = &applied.objects[1];
    assert_eq!(t1.properties["state"], "planned");
    assert_eq!(t1.properties["owner"], "ann");
    assert!(!t1.properties.contains_key("note"));
    assert_eq!(t1.revision, revision(&svc, "t1", "tester").await);
    assert_ne!(t1.revision, before);
    assert_eq!(applied.links[0].id, "t1-blocks-t2");

    let replayed = svc
        .apply_graph_changes_rpc(as_principal(request("r1", changes.clone()), "tester"))
        .await
        .unwrap()
        .into_inner();
    assert!(replayed.replayed);
    assert_eq!(replayed.objects.len(), 2);

    let conflict = svc
        .apply_graph_changes_rpc(as_principal(request("r1", vec![create("t3")]), "tester"))
        .await
        .unwrap_err();
    assert_eq!(conflict.code(), tonic::Code::AlreadyExists);

    // The revision read before the call is stale now; nothing is written.
    let stale = svc
        .apply_graph_changes_rpc(as_principal(
            request(
                "r2",
                vec![create("t4"), patch("t1", &before, &[("state", "x")], &[])],
            ),
            "tester",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    assert!(stale.message().starts_with("graph_change_conflict:"));
    assert!(svc.db.runtime().get_object("t4").unwrap().is_none());
}

#[tokio::test]
async fn refuses_a_change_the_single_record_rpc_refuses() {
    let svc = service();
    seed(&svc, "locked", &[("state", "open")]);
    let grant = security::Grant {
        id: "locked-admin".into(),
        object_id: "locked".into(),
        principal: "alice".into(),
        role: security::Role::Admin,
        created: 1,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
    let stored = svc.db.runtime().get_object("locked").unwrap().unwrap();
    let mut proposed = to_proto_obj(&stored);
    proposed.properties.insert("state".into(), "taken".into());
    proposed.updated = 2;
    let single = svc
        .update_object(as_principal(
            UpdateObjectRequest {
                object: Some(proposed),
                lease_precondition: None,
            },
            "bob",
        ))
        .await
        .unwrap_err();
    let alice_revision = revision(&svc, "locked", "alice").await;
    let batch = svc
        .apply_graph_changes_rpc(as_principal(
            request(
                "bob-1",
                vec![
                    create("bob-new"),
                    patch("locked", &alice_revision, &[("state", "taken")], &[]),
                ],
            ),
            "bob",
        ))
        .await
        .unwrap_err();
    assert_eq!(
        batch.code(),
        single.code(),
        "{} / {}",
        batch.message(),
        single.message()
    );
    assert!(svc.db.runtime().get_object("bob-new").unwrap().is_none());
    assert_eq!(
        svc.db
            .runtime()
            .get_object("locked")
            .unwrap()
            .unwrap()
            .properties["state"],
        "open"
    );
}

#[tokio::test]
async fn refuses_more_changes_than_the_cap() {
    let svc = service();
    let changes = (0..=crate::sekai::graph_changes::MAX_GRAPH_CHANGES)
        .map(|index| create(&format!("o{index}")))
        .collect();
    let error = svc
        .apply_graph_changes_rpc(as_principal(request("big", changes), "tester"))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}
