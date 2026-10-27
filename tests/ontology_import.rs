//! `sekaictl ontology import` through the shipped binaries (#1618).

use sekai_chisei::grpc::pb::sekai::{
    DefinitionMemberInput, EnsureTeamNamespaceRequest, GetDefinitionBranchRequest,
    GetDefinitionProposalRequest, GetPublishedDefinitionRevisionRequest,
    ImportDefinitionTreeRequest,
};
use tonic::Code;

use crate::ontology_export::{export, publish};
use crate::product_loop_backend_conformance::{Backend, LoopServer, bearer};

const INCIDENT: &str = r#"{"name":"incident","properties":["severity","title"],"required":["title"],"lint_suppressions":[{"rule":"orphan_object_type","reason":"import fixture"}]}"#;

fn import(server: &LoopServer, dir: &std::path::Path, commit: &str) -> String {
    server.sekaictl_ok(&[
        "ontology",
        "import",
        "--namespace",
        "import-a",
        "--dir",
        dir.to_str().unwrap(),
        "--source-commit",
        commit,
        "--target",
        &server.socket_str(),
    ])
}

async fn published_head(server: &LoopServer) -> String {
    server
        .sekai()
        .await
        .get_published_definition_revision(GetPublishedDefinitionRevisionRequest {
            namespace: "import-a".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("published: {error}\n{}", server.logs()))
        .into_inner()
        .revision
        .unwrap()
        .revision_digest
}

/// A tree import of one incident body, planned against `head`.
fn incident_import(commit: &str, body: &str, head: &str) -> ImportDefinitionTreeRequest {
    ImportDefinitionTreeRequest {
        namespace: "import-a".into(),
        branch_id: format!("import-{commit}"),
        proposal_id: format!("import-{commit}"),
        members: vec![DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "incident".into(),
            definition_json: body.into(),
            member_digest: String::new(),
        }],
        source_commit: commit.into(),
        idempotency_key: format!("import-{commit}"),
        expected_published_digest: head.into(),
    }
}

async fn branch_exists(server: &LoopServer, branch_id: &str) -> bool {
    match server
        .sekai()
        .await
        .get_definition_branch(GetDefinitionBranchRequest {
            namespace: "import-a".into(),
            branch_id: branch_id.into(),
        })
        .await
    {
        Ok(_) => true,
        Err(status) if status.code() == Code::NotFound => false,
        Err(status) => panic!("branch: {status}\n{}", server.logs()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_import_proposes_exactly_the_changed_definitions_and_records_its_commit() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    let dir = tempfile::tempdir().unwrap();
    publish(
        &server,
        "import-a",
        vec![
            ("object_type".into(), "incident".into(), INCIDENT.into()),
            (
                "function".into(),
                "sync/feed".into(),
                r#"{"name":"sync"}"#.into(),
            ),
        ],
    )
    .await;
    let tree = dir.path().join("tree");
    export(&server, "import-a", &tree);

    // An unchanged tree opens nothing.
    let output = import(&server, &tree, "aaaaaaa");
    assert!(output.contains("no proposal opened"), "{output}");
    assert!(!branch_exists(&server, "import-aaaaaaa").await);

    // One changed definition: a proposal with exactly that change.
    let incident = tree.join("object_type/incident.json");
    let body = std::fs::read_to_string(&incident).unwrap();
    std::fs::write(
        &incident,
        body.replace("\"severity\",", "\"owner\",\n    \"severity\","),
    )
    .unwrap();
    let output = import(&server, &tree, "bbbbbbb");
    assert!(
        output.contains("opened proposal import-bbbbbbb"),
        "{output}"
    );
    assert!(output.contains("changed object_type/incident"), "{output}");
    assert!(
        !output.contains("function/"),
        "only the changed definition: {output}"
    );
    let proposal = server
        .sekai()
        .await
        .get_definition_proposal(GetDefinitionProposalRequest {
            namespace: "import-a".into(),
            proposal_id: "import-bbbbbbb".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("proposal: {error}\n{}", server.logs()))
        .into_inner()
        .proposal
        .unwrap();
    assert_eq!(proposal.source_commit, "bbbbbbb");
    assert_eq!(proposal.status, "open", "import never merges");

    // Removing a function is breaking, and says so before any merge.
    std::fs::remove_file(tree.join("function/sync%2Ffeed.json")).unwrap();
    let output = import(&server, &tree, "ccccccc");
    assert!(output.contains("removed function/sync/feed"), "{output}");
    assert!(output.contains("compatibility: breaking"), "{output}");
}

/// A namespace editor without schema admin can create branches, but an
/// import that would change a definition is refused before anything is
/// written.
#[tokio::test(flavor = "multi_thread")]
async fn an_import_without_permission_fails_closed_and_creates_no_branch() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    publish(
        &server,
        "import-a",
        vec![("object_type".into(), "incident".into(), INCIDENT.into())],
    )
    .await;
    let editor = server.token("import-editor");
    let mut sekai = server.sekai().await;
    sekai
        .ensure_team_namespace(EnsureTeamNamespaceRequest {
            namespace: "import-a".into(),
            principal: "import-editor".into(),
            role: "editor".into(),
        })
        .await
        .unwrap_or_else(|error| panic!("grant: {error}\n{}", server.logs()));

    let head = published_head(&server).await;
    let refused = sekai
        .import_definition_tree(bearer(
            &editor,
            incident_import(
                "ddddddd",
                r#"{"name":"incident","properties":["title"]}"#,
                &head,
            ),
        ))
        .await
        .unwrap_err();

    assert_eq!(refused.code(), Code::PermissionDenied, "{refused}");
    assert!(!branch_exists(&server, "import-ddddddd").await);
}

/// The same commit with other contents is a conflict, and a tree compared
/// with an older head is refused rather than reverting what merged since.
#[tokio::test(flavor = "multi_thread")]
async fn a_reused_commit_and_a_stale_tree_are_refused() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    publish(
        &server,
        "import-a",
        vec![("object_type".into(), "incident".into(), INCIDENT.into())],
    )
    .await;
    let head = published_head(&server).await;
    let mut sekai = server.sekai().await;
    let first = INCIDENT.replace("\"severity\",", "\"owner\",\"severity\",");
    sekai
        .import_definition_tree(incident_import("eeeeeee", &first, &head))
        .await
        .unwrap_or_else(|error| panic!("import: {error}\n{}", server.logs()));
    // The same request replays.
    sekai
        .import_definition_tree(incident_import("eeeeeee", &first, &head))
        .await
        .unwrap_or_else(|error| panic!("replay: {error}\n{}", server.logs()));

    let other = INCIDENT.replace("\"severity\",", "\"region\",\"severity\",");
    let conflict = sekai
        .import_definition_tree(incident_import("eeeeeee", &other, &head))
        .await
        .unwrap_err();
    assert_eq!(
        conflict.code(),
        Code::AlreadyExists,
        "the same key with other contents conflicts: {conflict}"
    );

    // Into a namespace that had published nothing: the first import seeds
    // its genesis, and a retry of the same request still replays.
    let mut fresh = incident_import("abcdef0", &first, "");
    fresh.namespace = "import-b".into();
    for attempt in ["first", "retry"] {
        sekai
            .import_definition_tree(fresh.clone())
            .await
            .unwrap_or_else(|error| panic!("{attempt}: {error}\n{}", server.logs()));
    }

    let stale = sekai
        .import_definition_tree(incident_import(
            "fffffff",
            &other,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ))
        .await
        .unwrap_err();
    assert_eq!(stale.code(), Code::FailedPrecondition, "{stale}");
    assert!(!branch_exists(&server, "import-fffffff").await);
}
