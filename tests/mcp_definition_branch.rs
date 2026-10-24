//! MCP definition-branch tools: agent drafts, human approves (#1311).

use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ApproveDefinitionProposalRequest, MergeDefinitionProposalRequest,
};
use sekai_chisei::mcp_adapter::{InProcessSurface, handle_message, well_known_tools};
use serde_json::{Value, json};
use tonic::Request;
use tonic::metadata::MetadataValue;

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
    let surface = InProcessSurface::synthetic().await.unwrap();
    assert!(
        !well_known_tools()
            .iter()
            .any(|tool| tool.contains("approve") || tool.contains("merge"))
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

    let proposed = handle_message(
        &surface,
        call(
            6,
            "sekai.definitions.proposal.create",
            json!({
                "branchId": "feature",
                "proposalId": "cs-1",
                "baseDigest": parent,
                "candidateDigest": candidate,
                "evalPlanDigests": [format!("sha256:{}", "e".repeat(64))],
                "namedForeignDigests": [format!("sha256:{}", "f".repeat(64))],
                "idempotencyKey": "propose-1"
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        output(&proposed)["proposal"]["status"],
        "open",
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

    let agent_approve = surface
        .sekai
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
                proposal_id: "cs-1".into(),
                idempotency_key: "approve-agent".into(),
            },
            &surface.principal,
        ))
        .await
        .unwrap_err();
    assert_eq!(agent_approve.code(), tonic::Code::PermissionDenied);
    assert_eq!(agent_approve.message(), "proposal creator cannot approve");

    let agent_merge = surface
        .sekai
        .merge_definition_proposal(with_principal(
            MergeDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
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

    let guest_approve = surface
        .sekai
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
                proposal_id: "cs-1".into(),
                idempotency_key: "approve-guest".into(),
            },
            "agent-guest",
        ))
        .await
        .unwrap_err();
    assert_eq!(guest_approve.code(), tonic::Code::PermissionDenied);

    surface
        .sekai
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
                proposal_id: "cs-1".into(),
                idempotency_key: "approve-human".into(),
            },
            "root",
        ))
        .await
        .unwrap();
    let merged = surface
        .sekai
        .merge_definition_proposal(with_principal(
            MergeDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
                proposal_id: "cs-1".into(),
                expected_published_digest: parent,
                idempotency_key: "merge-human".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(merged.proposal.unwrap().status, "merged");
}
