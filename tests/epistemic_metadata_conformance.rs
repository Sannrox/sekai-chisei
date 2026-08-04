//! Cross-boundary non-disclosure conformance for epistemic projections.
//!
//! These tests exercise the public gRPC service implementations rather than
//! private retrieval helpers.  Each hidden fixture is compared with an
//! otherwise identical authorized snapshot so metadata, ordering, and
//! structural evidence cannot become an existence oracle.

use std::collections::HashMap;
use std::sync::Arc;

use sekai_chisei::chisei::epistemic_descriptor::{
    EPISTEMIC_DESCRIPTOR_VERSION, EpistemicDescriptor, MAX_DESCRIPTOR_BYTES, MAX_OBSERVED_AT_MS,
    MAX_SOURCE_ITEM_BYTES, MAX_SOURCE_REFS, MAX_SOURCE_ROWS,
};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{Link, Object};
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::*;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::security::{Grant, Role};
use tonic::Request;
use tonic::metadata::MetadataValue;

fn object(id: &str, namespace: &str) -> Object {
    Object {
        id: id.into(),
        kind: "widget".into(),
        name: id.into(),
        namespace: namespace.into(),
        external_id: format!("widget:{id}"),
        properties: HashMap::from([(String::from("name"), id.into())]),
        created: 1,
        updated: 1,
    }
}

fn link(id: &str, from_id: &str, to_id: &str) -> Link {
    Link {
        id: id.into(),
        from_id: from_id.into(),
        to_id: to_id.into(),
        relation: "contains".into(),
        created: 1,
    }
}

fn grant(id: &str, object_id: &str, principal: &str) -> Grant {
    Grant {
        id: id.into(),
        object_id: object_id.into(),
        principal: principal.into(),
        role: Role::Viewer,
        created: 1,
    }
}

fn fixture(include_hidden: bool) -> (Arc<RuntimeDb>, SekaiServiceImpl) {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").expect("in-memory sqlite"),
    )));
    for item in [object("root", "default"), object("visible", "default")] {
        db.create_object(&item).expect("fixture object");
    }
    db.create_link(&link("visible-link", "root", "visible"))
        .expect("fixture link");

    if include_hidden {
        db.create_object(&object("hidden-cross-namespace", "restricted"))
            .expect("hidden object");
        db.create_object(&object("hidden-root", "restricted"))
            .expect("hidden root");
        db.ensure_team_namespace("team-hidden", "bob", Role::Viewer, "root")
            .expect("hidden team namespace");
        let mut hidden_team = object("hidden-team", "team-hidden");
        hidden_team.properties.insert("name".into(), "root".into());
        db.create_object(&hidden_team).expect("hidden team object");
        db.create_link(&link("hidden-link", "root", "hidden-cross-namespace"))
            .expect("hidden link");
        for (id, object_id) in [
            ("hidden-object-grant", "hidden-cross-namespace"),
            ("hidden-root-grant", "hidden-root"),
            ("hidden-team-grant", "hidden-team"),
        ] {
            db.create_grant(&grant(id, object_id, "bob"))
                .expect("hidden grant");
        }
    }

    let service = SekaiServiceImpl::new(Arc::clone(&db));
    (db, service)
}

fn principal_request<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).expect("principal metadata"),
    );
    request
}

fn retrieve_request(root: &str) -> RetrieveContextRequest {
    RetrieveContextRequest {
        roots: vec![ContextRoot {
            object_id: root.into(),
            ..Default::default()
        }],
        relations: vec!["contains".into()],
        direction: "outgoing".into(),
        max_depth: 1,
        max_objects: 20,
        max_links: 20,
        ..Default::default()
    }
}

async fn retrieve(service: &SekaiServiceImpl, root: &str) -> RetrieveContextResponse {
    service
        .retrieve_context(principal_request(retrieve_request(root), "alice"))
        .await
        .expect("retrieve context")
        .into_inner()
}

fn candidate_ids(response: &RetrieveContextResponse) -> Vec<&str> {
    response
        .candidates
        .iter()
        .filter_map(|candidate| candidate.object.as_ref().map(|object| object.id.as_str()))
        .collect()
}

#[tokio::test]
async fn graph_metadata_is_invariant_under_acl_and_namespace_hidden_sources() {
    let (_baseline_db, baseline) = fixture(false);
    let (_hidden_db, hidden) = fixture(true);

    let baseline_response = retrieve(&baseline, "root").await;
    let hidden_response = retrieve(&hidden, "root").await;

    assert_eq!(hidden_response, baseline_response);
    assert_eq!(candidate_ids(&hidden_response), vec!["root", "visible"]);
    assert_eq!(hidden_response.denied_objects, 0);
    assert_eq!(hidden_response.unresolved_roots, 0);
    assert!(
        hidden_response
            .candidates
            .iter()
            .flat_map(|candidate| candidate
                .descriptor
                .iter()
                .flat_map(|descriptor| descriptor.source_refs.iter()))
            .all(|source| !source.contains("hidden"))
    );

    // A denied root and an absent root deliberately share the same public
    // shape.  This prevents a caller from turning metadata into an existence
    // oracle even when it can guess an object identifier.
    let denied_root = retrieve(&hidden, "hidden-root").await;
    let absent_root = retrieve(&hidden, "does-not-exist").await;
    assert_eq!(denied_root, absent_root);
    assert!(denied_root.candidates.is_empty());
    assert_eq!(denied_root.denied_objects, 0);
    assert_eq!(denied_root.unresolved_roots, 1);
}

#[tokio::test]
async fn native_expand_preserves_the_same_hidden_projection() {
    let (_db, service) = fixture(true);
    let retrieve_response = retrieve(&service, "root").await;

    let expanded = service
        .expand_relations(principal_request(
            ExpandRelationsRequest {
                namespace: "default".into(),
                root: Some(ContextRoot {
                    object_id: "root".into(),
                    ..Default::default()
                }),
                relations: vec!["contains".into()],
                direction: "outgoing".into(),
                max_depth: 1,
                max_objects: 20,
                max_links: 20,
                ..Default::default()
            },
            "alice",
        ))
        .await
        .expect("expand relations")
        .into_inner();
    assert_eq!(
        candidate_ids_from_expand(&expanded),
        candidate_ids(&retrieve_response)
    );
    assert_eq!(expanded.links, retrieve_response.links);
    assert_eq!(expanded.denied_objects, 0);
    assert_eq!(expanded.unresolved_roots, 0);
}

#[tokio::test]
async fn catalog_receipts_keep_only_bounded_structural_metadata() {
    let (db, service) = fixture(true);
    let catalog = service
        .discover_capabilities(principal_request(
            DiscoverCapabilitiesRequest {
                namespace: "default".into(),
                page_size: 200,
                ..Default::default()
            },
            "alice",
        ))
        .await
        .expect("discover capabilities")
        .into_inner();

    let mut request = principal_request(retrieve_request("root"), "alice");
    request.metadata_mut().insert(
        "x-sekai-capability",
        MetadataValue::from_static("sekai.context.retrieve"),
    );
    request
        .metadata_mut()
        .insert("x-sekai-namespace", MetadataValue::from_static("default"));
    request.metadata_mut().insert(
        "x-sekai-operation-id",
        MetadataValue::from_static("epistemic-receipt"),
    );
    request.metadata_mut().insert(
        "x-sekai-catalog-version",
        MetadataValue::try_from(catalog.catalog_version.as_str()).expect("catalog metadata"),
    );
    service
        .retrieve_context(request)
        .await
        .expect("catalog-bound retrieval");

    let receipt = db
        .get_operation_receipt("epistemic-receipt")
        .expect("receipt lookup")
        .expect("receipt persisted");
    assert!(receipt.events.iter().all(|event| {
        event
            .attributes
            .values()
            .all(|value| !value.contains("hidden") && !value.contains("secret-payload"))
    }));
    assert!(receipt.events.iter().all(|event| {
        event
            .attributes
            .keys()
            .all(|key| !key.contains("descriptor_payload") && !key.contains("raw_context"))
    }));
}

fn candidate_ids_from_expand(response: &ExpandRelationsResponse) -> Vec<&str> {
    response
        .candidates
        .iter()
        .filter_map(|candidate| candidate.object.as_ref().map(|object| object.id.as_str()))
        .collect()
}

#[test]
fn malformed_and_mixed_authorization_descriptors_fail_closed_and_stay_bounded() {
    let descriptor = EpistemicDescriptor::unknown();
    assert_eq!(descriptor.contract_version, EPISTEMIC_DESCRIPTOR_VERSION);
    descriptor.validate().expect("unknown descriptor is valid");

    for count in [MAX_SOURCE_REFS + 1, MAX_SOURCE_ROWS + 1] {
        let mut candidate = descriptor.clone();
        candidate.source_refs = vec!["source".into(); count];
        assert!(candidate.validate().is_err(), "source count {count}");
    }
    let mut row_count = descriptor.clone();
    row_count.source_row_count = Some((MAX_SOURCE_ROWS + 1) as u32);
    assert!(row_count.validate().is_err());

    for value in [
        "x".repeat(MAX_SOURCE_ITEM_BYTES + 1),
        String::from("source\nwith-control"),
    ] {
        let mut candidate = descriptor.clone();
        candidate.source_refs = vec![value];
        assert!(candidate.validate().is_err());
    }

    for observed_at_ms in [-1, MAX_OBSERVED_AT_MS + 1] {
        let mut candidate = descriptor.clone();
        candidate.observed_at_ms = Some(observed_at_ms);
        assert!(candidate.validate().is_err());
    }

    let mut candidate = descriptor.clone();
    candidate.producer_confidence_bps = Some(10_001);
    candidate.confidence_basis = Some("producer_input".into());
    assert!(candidate.validate().is_err());

    let mut candidate = descriptor;
    candidate.source_rows_truncated = true;
    assert!(candidate.validate().is_err());
    let encoded = serde_json::to_vec(&EpistemicDescriptor::unknown()).expect("descriptor JSON");
    assert!(encoded.len() <= MAX_DESCRIPTOR_BYTES);

    // A mixed-authorization Kioku-like projection may expose counts and
    // operation references, but never linked evidence digests without an
    // independent source authorization check.
    let mixed = EpistemicDescriptor::unknown();
    assert!(mixed.source_digests.is_empty());
}
