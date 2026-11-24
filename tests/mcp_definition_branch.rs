//! MCP definition-branch tools: agent drafts, human reviews and publishes over
//! default-build gRPC (#1311, #2095, #2407).

use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
use sekai_chisei::grpc::pb::sekai::{
    ApproveDefinitionProposalRequest, CloseDefinitionProposalRequest, GetDefinitionBranchRequest,
    GetDefinitionCertificationGateRequest, GetDefinitionMemberRequest,
    GetDefinitionProposalRequest, ListPublishedDefinitionRevisionsRequest,
    MergeDefinitionProposalRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::mcp_adapter::{InProcessSurface, handle_message, well_known_tools};
use sekai_chisei::rpc_maturity::RpcMaturityLayer;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tower::Layer;

fn call(id: i64, name: &str, input: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": {"operation_id": format!("op-def-{id}"), "input": input}
        }
    })
}

fn output(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    &reply["result"]["structuredContent"]["output"]
}

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).expect("principal"),
    );
    request
}

#[tokio::test]
async fn mcp_definition_branch_opens_a_proposal_for_human_review() {
    let mut surface = InProcessSurface::synthetic().await.unwrap();
    surface.experimental_rpcs = false;
    assert!(
        !well_known_tools()
            .iter()
            .any(|tool| tool.contains("approve") || tool.contains("merge"))
    );

    let search = handle_message(
        &surface,
        call(0, "sekai.search.query", json!({"text": "Ticket"})),
    )
    .await
    .unwrap();
    assert_eq!(
        search["result"]["structuredContent"]["code"], "failed_precondition",
        "{search}"
    );

    let created = handle_message(
        &surface,
        call(
            1,
            "sekai.definitions.branch.create",
            json!({
                "branchId": "feature",
                "parentRevisionDigest": "",
                "idempotencyKey": "create-1"
            }),
        ),
    )
    .await
    .unwrap();
    let parent = output(&created)["branch"]["headRevisionDigest"]
        .as_str()
        .expect("parent digest")
        .to_string();

    let first = handle_message(
        &surface,
        call(
            2,
            "sekai.definitions.branch.edit",
            json!({
                "branchId": "feature",
                "expectedHeadDigest": parent,
                "upserts": [{
                    "memberKind": "object_type",
                    "memberId": "Ticket",
                    "definitionJson": "{\"name\":\"Ticket\",\"properties\":[\"title\"]}",
                    "memberDigest": ""
                }],
                "removals": [],
                "idempotencyKey": "edit-1"
            }),
        ),
    )
    .await
    .unwrap();
    let after_first = output(&first)["revision"]["revisionDigest"]
        .as_str()
        .expect("first edit digest")
        .to_string();

    let second = handle_message(
        &surface,
        call(
            3,
            "sekai.definitions.branch.edit",
            json!({
                "branchId": "feature",
                "expectedHeadDigest": after_first,
                "upserts": [{
                    "memberKind": "object_type",
                    "memberId": "Ticket",
                    "definitionJson": "{\"name\":\"Ticket\",\"properties\":[\"title\",\"priority\"],\"lint_suppressions\":[{\"rule\":\"orphan_object_type\",\"reason\":\"reviewed by a human\"}]}",
                    "memberDigest": ""
                }],
                "removals": [],
                "idempotencyKey": "edit-2"
            }),
        ),
    )
    .await
    .unwrap();
    let candidate = output(&second)["revision"]["revisionDigest"]
        .as_str()
        .expect("second edit digest")
        .to_string();

    let diff = handle_message(
        &surface,
        call(
            4,
            "sekai.definitions.diff",
            json!({
                "fromRevisionDigest": parent,
                "toRevisionDigest": candidate
            }),
        ),
    )
    .await
    .unwrap();
    let added = output(&diff)["diff"]["added"]
        .as_array()
        .expect("added members");
    assert!(
        added.iter().any(|change| change["memberId"] == "Ticket"),
        "{diff}"
    );

    let impact = handle_message(
        &surface,
        call(
            5,
            "sekai.definitions.impact",
            json!({
                "fromRevisionDigest": parent,
                "toRevisionDigest": candidate
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(output(&impact)["completeness"], "complete", "{impact}");

    let plan_digest = surface.seed_evaluation_plan(&surface.namespace).unwrap();
    let propose = |id: i64, eval_plan_digest: String| {
        call(
            id,
            "sekai.definitions.proposal.create",
            json!({
                "branchId": "feature",
                "proposalId": "cs-1",
                "baseDigest": parent,
                "candidateDigest": candidate,
                "evalPlanDigests": [eval_plan_digest],
                "namedForeignDigests": [format!("sha256:{}", "f".repeat(64))],
                "idempotencyKey": "propose-1"
            }),
        )
    };

    // Plan digests are checked through an experimental lookup, so naming one
    // fails closed while experimental RPCs are off (#3174).
    let gated = handle_message(&surface, propose(60, plan_digest.clone()))
        .await
        .unwrap();
    assert_eq!(
        gated["result"]["structuredContent"]["code"], "failed_precondition",
        "{gated}"
    );
    surface.experimental_rpcs = true;

    let unknown = handle_message(&surface, propose(61, format!("sha256:{}", "e".repeat(64))))
        .await
        .unwrap();
    assert_eq!(
        unknown["result"]["structuredContent"]["code"], "failed_precondition",
        "{unknown}"
    );

    let proposed = handle_message(&surface, propose(6, plan_digest.clone()))
        .await
        .unwrap();
    assert_eq!(
        output(&proposed)["proposal"]["status"],
        "open",
        "{proposed}"
    );
    assert_eq!(
        output(&proposed)["proposal"]["evalPlanDigests"],
        json!([plan_digest]),
        "{proposed}"
    );
    assert_eq!(
        output(&proposed)["proposal"]["createdBy"],
        surface.principal,
        "{proposed}"
    );

    let merge_over_mcp = handle_message(
        &surface,
        call(
            7,
            "sekai.definitions.proposal.merge",
            json!({
                "proposalId": "cs-1",
                "expectedPublishedDigest": parent,
                "idempotencyKey": "merge-mcp"
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        merge_over_mcp["result"]["structuredContent"]["code"], "unimplemented",
        "{merge_over_mcp}"
    );

    // The human half runs on a served plane with experimental RPCs off, the
    // gate a default build applies (#2407).
    let human = default_plane(surface.sekai.clone()).await;
    let mut grpc = SekaiServiceClient::connect(human.endpoint.clone())
        .await
        .unwrap();
    let namespace = surface.namespace.clone();

    // Close stays experimental, so the gate is live on this plane.
    let close = grpc
        .close_definition_proposal(with_principal(
            CloseDefinitionProposalRequest {
                namespace: namespace.clone(),
                proposal_id: "cs-1".into(),
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(close.code(), tonic::Code::FailedPrecondition);

    let agent_approve = grpc
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: namespace.clone(),
                proposal_id: "cs-1".into(),
                idempotency_key: "approve-agent".into(),
            },
            &surface.principal,
        ))
        .await
        .unwrap_err();
    assert_eq!(agent_approve.code(), tonic::Code::PermissionDenied);
    assert_eq!(agent_approve.message(), "proposal creator cannot approve");

    let agent_merge = grpc
        .merge_definition_proposal(with_principal(
            MergeDefinitionProposalRequest {
                namespace: namespace.clone(),
                proposal_id: "cs-1".into(),
                expected_published_digest: parent.clone(),
                idempotency_key: "merge-agent".into(),
            },
            &surface.principal,
        ))
        .await
        .unwrap_err();
    assert_eq!(agent_merge.code(), tonic::Code::PermissionDenied);
    assert_eq!(agent_merge.message(), "proposal creator cannot merge");

    let guest_approve = grpc
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: namespace.clone(),
                proposal_id: "cs-1".into(),
                idempotency_key: "approve-guest".into(),
            },
            "agent-guest",
        ))
        .await
        .unwrap_err();
    assert_eq!(guest_approve.code(), tonic::Code::PermissionDenied);

    let branch = grpc
        .get_definition_branch(with_principal(
            GetDefinitionBranchRequest {
                namespace: namespace.clone(),
                branch_id: "feature".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .branch
        .unwrap();
    assert_eq!(branch.head_revision_digest, candidate);

    let proposal = grpc
        .get_definition_proposal(with_principal(
            GetDefinitionProposalRequest {
                namespace: namespace.clone(),
                proposal_id: "cs-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    assert_eq!(proposal.status, "open");
    assert_eq!(proposal.created_by, surface.principal);

    let member = grpc
        .get_definition_member(with_principal(
            GetDefinitionMemberRequest {
                namespace: namespace.clone(),
                revision_digest: candidate.clone(),
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .member
        .unwrap();
    assert!(member.definition_json.contains("priority"), "{member:?}");

    let gate = grpc
        .get_definition_certification_gate(with_principal(
            GetDefinitionCertificationGateRequest {
                namespace: namespace.clone(),
                revision_digest: candidate.clone(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .gate
        .unwrap();
    assert_eq!(gate.revision_digest, candidate);

    grpc.approve_definition_proposal(with_principal(
        ApproveDefinitionProposalRequest {
            namespace: namespace.clone(),
            proposal_id: "cs-1".into(),
            idempotency_key: "approve-human".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let merged = grpc
        .merge_definition_proposal(with_principal(
            MergeDefinitionProposalRequest {
                namespace: namespace.clone(),
                proposal_id: "cs-1".into(),
                expected_published_digest: parent.clone(),
                idempotency_key: "merge-human".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let merged = merged.proposal.unwrap();
    assert_eq!(merged.status, "merged");

    let history = grpc
        .list_published_definition_revisions(with_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace,
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    let newest = history.entries.first().expect("published revision");
    assert_eq!(newest.revision_digest, candidate);
    assert_eq!(newest.proposal_id, "cs-1");
    assert_eq!(newest.previous_published_digest, parent);
    human.stop().await;
}

/// A plane serving `sekai` on an ephemeral port behind the maturity gate with
/// experimental RPCs off.
struct DefaultPlane {
    endpoint: String,
    stop: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<()>,
}

impl DefaultPlane {
    async fn stop(self) {
        let _ = self.stop.send(());
        self.server.await.unwrap();
    }
}

async fn default_plane(sekai: SekaiServiceImpl) -> DefaultPlane {
    let service = RpcMaturityLayer::new(false).layer(SekaiServiceServer::new(sekai));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    DefaultPlane {
        endpoint,
        stop,
        server,
    }
}
