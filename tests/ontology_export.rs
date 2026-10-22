//! `sekaictl ontology export` round trip through the shipped binaries (#1617).

use std::collections::BTreeMap;
use std::path::Path;

use sekai_chisei::grpc::pb::sekai::{
    ApplyDefinitionBranchEditRequest, ApproveDefinitionProposalRequest,
    ClassificationIncomparablePair, ClassificationLattice, ClassificationParentEdge,
    CreateDefinitionBranchRequest, CreateDefinitionProposalRequest, CreateObjectRequest,
    DefinitionMemberInput, MergeDefinitionProposalRequest, Object, PutClassificationLatticeRequest,
};
use tonic::Request;

use crate::product_loop_backend_conformance::{Backend, LoopServer};

const OBJECT_DATA: &str = "object-data-must-not-be-exported";

/// Publishes `members` as the namespace's first definition revision through the
/// reviewed proposal flow.
async fn publish(server: &LoopServer, namespace: &str, members: Vec<(String, String, String)>) {
    let mut sekai = server.sekai().await;
    let branch = sekai
        .create_definition_branch(CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "import".into(),
            parent_revision_digest: String::new(),
            idempotency_key: format!("{namespace}-branch"),
        })
        .await
        .unwrap_or_else(|error| panic!("branch: {error}\n{}", server.logs()))
        .into_inner()
        .branch
        .expect("branch");
    let genesis = branch.head_revision_digest;
    let candidate = sekai
        .apply_definition_branch_edit(ApplyDefinitionBranchEditRequest {
            namespace: namespace.into(),
            branch_id: "import".into(),
            expected_head_digest: genesis.clone(),
            upserts: members
                .into_iter()
                .map(
                    |(member_kind, member_id, definition_json)| DefinitionMemberInput {
                        member_kind,
                        member_id,
                        definition_json,
                        member_digest: String::new(),
                    },
                )
                .collect(),
            removals: Vec::new(),
            idempotency_key: format!("{namespace}-edit"),
        })
        .await
        .unwrap_or_else(|error| panic!("edit: {error}\n{}", server.logs()))
        .into_inner()
        .revision
        .expect("candidate")
        .revision_digest;
    sekai
        .create_definition_proposal(CreateDefinitionProposalRequest {
            namespace: namespace.into(),
            branch_id: "import".into(),
            proposal_id: "import".into(),
            base_digest: genesis.clone(),
            candidate_digest: candidate,
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: format!("{namespace}-propose"),
        })
        .await
        .unwrap_or_else(|error| panic!("propose: {error}\n{}", server.logs()));
    sekai
        .approve_definition_proposal(ApproveDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: "import".into(),
            idempotency_key: format!("{namespace}-approve"),
        })
        .await
        .unwrap_or_else(|error| panic!("approve: {error}\n{}", server.logs()));
    sekai
        .merge_definition_proposal(MergeDefinitionProposalRequest {
            namespace: namespace.into(),
            proposal_id: "import".into(),
            idempotency_key: format!("{namespace}-merge"),
            expected_published_digest: genesis,
        })
        .await
        .unwrap_or_else(|error| panic!("merge: {error}\n{}", server.logs()));
}

async fn put_lattice(server: &LoopServer, namespace: &str, lattice: ClassificationLattice) {
    server
        .sekai()
        .await
        .put_classification_lattice(Request::new(PutClassificationLatticeRequest {
            lattice: Some(ClassificationLattice {
                namespace: namespace.into(),
                ..lattice
            }),
        }))
        .await
        .unwrap_or_else(|error| panic!("lattice: {error}\n{}", server.logs()));
}

fn export(server: &LoopServer, namespace: &str, out: &Path) -> BTreeMap<String, Vec<u8>> {
    server.sekaictl_ok(&[
        "ontology",
        "export",
        "--namespace",
        namespace,
        "--out",
        out.to_str().unwrap(),
        "--target",
        &server.socket_str(),
    ]);
    let mut tree = BTreeMap::new();
    read_tree(out, out, &mut tree);
    tree
}

fn read_tree(root: &Path, dir: &Path, tree: &mut BTreeMap<String, Vec<u8>>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            read_tree(root, &path, tree);
        } else {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            tree.insert(relative, std::fs::read(&path).unwrap());
        }
    }
}

fn decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            out.push(u8::from_str_radix(&segment[index + 1..index + 3], 16).unwrap());
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The definition members a tree holds, as `(kind, id, json)`.
fn members_of(tree: &BTreeMap<String, Vec<u8>>) -> Vec<(String, String, String)> {
    tree.iter()
        .filter(|(path, _)| path.as_str() != "layout.json" && !path.starts_with("markings/"))
        .map(|(path, body)| {
            let (kind, file) = path.split_once('/').unwrap();
            let id = decode(file.strip_suffix(".json").unwrap());
            (decode(kind), id, String::from_utf8(body.clone()).unwrap())
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_export_applied_into_an_empty_namespace_exports_byte_identically() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    let dir = tempfile::tempdir().unwrap();
    publish(
        &server,
        "export-a",
        vec![
            (
                "object_type".into(),
                "incident".into(),
                r#"{"name":"incident","properties":["severity","title"],"required":["title"],"access_marking":"confidential"}"#.into(),
            ),
            (
                "link_type".into(),
                "incident.affects".into(),
                r#"{"name":"affects"}"#.into(),
            ),
            ("action_type".into(), "close".into(), r#"{"name":"close","mode":"manual"}"#.into()),
            ("function".into(), "sync/feed".into(), r#"{"name":"sync"}"#.into()),
        ],
    )
    .await;
    // A credential the namespace's operators hold; export reads definitions only.
    let credential = server.token("exporter");
    put_lattice(
        &server,
        "export-a",
        ClassificationLattice {
            contract_version: "sekai.classification-lattice/v1".into(),
            namespace: String::new(),
            tokens: vec![
                "public".into(),
                "confidential".into(),
                "health".into(),
                "secret".into(),
            ],
            parents: vec![
                ClassificationParentEdge {
                    child: "public".into(),
                    parent: "confidential".into(),
                },
                ClassificationParentEdge {
                    child: "confidential".into(),
                    parent: "secret".into(),
                },
                ClassificationParentEdge {
                    child: "health".into(),
                    parent: "secret".into(),
                },
            ],
            incomparable: vec![ClassificationIncomparablePair {
                left: "confidential".into(),
                right: "health".into(),
            }],
            digest: String::new(),
        },
    )
    .await;
    server
        .sekai()
        .await
        .create_object(Request::new(CreateObjectRequest {
            object: Some(Object {
                id: "incident-1".into(),
                kind: "incident".into(),
                name: OBJECT_DATA.into(),
                namespace: "export-a".into(),
                properties: [("severity".to_string(), OBJECT_DATA.to_string())].into(),
                ..Default::default()
            }),
            lease_precondition: None,
        }))
        .await
        .unwrap_or_else(|error| panic!("object: {error}\n{}", server.logs()));

    let first = export(&server, "export-a", &dir.path().join("first"));
    let again = export(&server, "export-a", &dir.path().join("again"));
    assert_eq!(first, again, "exporting twice gives identical trees");
    assert!(first.contains_key("function/sync%2Ffeed.json"));
    assert!(first.contains_key("link_type/incident%2Eaffects.json"));
    assert!(first.contains_key("markings/lattice.json"));
    assert!(first.contains_key("layout.json"));
    for (path, body) in &first {
        let body = String::from_utf8_lossy(body);
        assert!(!body.contains(&credential), "{path} leaks the credential");
        assert!(!body.contains(OBJECT_DATA), "{path} leaks object data");
        assert!(!body.contains("export-a"), "{path} names its namespace");
    }

    // Apply the tree into an empty namespace through the governed flow.
    publish(&server, "export-b", members_of(&first)).await;
    let lattice: serde_json::Value =
        serde_json::from_slice(&first["markings/lattice.json"]).unwrap();
    let pairs =
        |key: &str| -> Vec<[String; 2]> { serde_json::from_value(lattice[key].clone()).unwrap() };
    put_lattice(
        &server,
        "export-b",
        ClassificationLattice {
            contract_version: lattice["contract_version"].as_str().unwrap().into(),
            namespace: String::new(),
            tokens: serde_json::from_value(lattice["tokens"].clone()).unwrap(),
            parents: pairs("parents")
                .into_iter()
                .map(|[child, parent]| ClassificationParentEdge { child, parent })
                .collect(),
            incomparable: pairs("incomparable")
                .into_iter()
                .map(|[left, right]| ClassificationIncomparablePair { left, right })
                .collect(),
            digest: String::new(),
        },
    )
    .await;
    let round_trip = export(&server, "export-b", &dir.path().join("round-trip"));
    assert_eq!(first, round_trip, "export, apply, export is byte-identical");
    assert_eq!(server.panics(), 0, "{}", server.logs());
}
