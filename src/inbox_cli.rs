//! `sekaictl inbox` (#2203): what waits on the caller in one namespace. The
//! client merges each plane's own listing; neither plane aggregates the
//! other. Sekai answers `ListPendingDecisions`, or, on a plane without it,
//! `ListActionInstances` with `decidable_by_caller`. Chisei answers its open
//! memory candidates, and the local Chisei store its proposed learning
//! changes, as `admin learning list` reads them. A half whose service is not
//! served is reported unavailable, so a single-plane deployment shows its own
//! half.

use crate::grpc::client::{GatewayClient, connect_sekai};
use crate::grpc::pb::chisei::ListKiokuCandidatesRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    ListActionInstancesRequest, ListPendingDecisionsRequest, PendingDecision, PendingDecisionKind,
};
use serde_json::{Value, json};
use tonic::Code;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl inbox --namespace <name> [--limit <n>]"
}

pub async fn run_inbox_command(args: Vec<String>) -> Result<(), BoxErr> {
    let namespace = flag(&args, "--namespace").ok_or_else(|| std::io::Error::other(usage()))?;
    let limit = flag(&args, "--limit")
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(100);
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let channel = connect_sekai(&target).await?;
    let sekai = sekai_decisions(
        &mut SekaiServiceClient::new(channel.clone()),
        &namespace,
        limit,
    )
    .await?;
    let memory_candidates =
        memory_candidates(&mut ChiseiServiceClient::new(channel), &namespace, limit).await?;
    let learning_changes = match crate::learning_cli::proposed_changes(&namespace) {
        Ok(changes) => serde_json::to_value(changes)?,
        Err(_) => json!({ "unavailable": true }),
    };
    let inbox = json!({
        "namespace": namespace,
        "sekai": sekai,
        "chisei": {
            "memory_candidates": memory_candidates,
            "learning_changes": learning_changes,
        },
    });
    println!("{}", serde_json::to_string_pretty(&inbox)?);
    Ok(())
}

/// Whether a refusal means the plane does not serve the RPC: unimplemented,
/// held back by the maturity gate (unclassified or experimental), or outside
/// an old plane's tenant allowlist.
fn unserved(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        Code::Unimplemented | Code::FailedPrecondition | Code::PermissionDenied
    )
}

/// Sekai's half: `{source, decisions, next_page_token}`, or
/// `{unavailable: true}` when the plane serves neither listing.
async fn sekai_decisions(
    client: &mut SekaiServiceClient<GatewayClient>,
    namespace: &str,
    limit: u32,
) -> Result<Value, BoxErr> {
    let pending = client
        .list_pending_decisions(ListPendingDecisionsRequest {
            namespace: namespace.into(),
            kinds: Vec::new(),
            limit,
            page_token: String::new(),
        })
        .await;
    match pending {
        Ok(response) => {
            let response = response.into_inner();
            return Ok(json!({
                "source": "ListPendingDecisions",
                "decisions": response.decisions.iter().map(decision_json).collect::<Vec<_>>(),
                "next_page_token": response.next_page_token,
            }));
        }
        Err(status) if unserved(&status) => {}
        Err(status) => return Err(status.into()),
    }
    let fallback = client
        .list_action_instances(ListActionInstancesRequest {
            namespace: namespace.into(),
            limit,
            decidable_by_caller: true,
            ..Default::default()
        })
        .await;
    match fallback {
        Ok(response) => Ok(json!({
            "source": "ListActionInstances",
            "decisions": response
                .into_inner()
                .instances
                .into_iter()
                .map(|instance| decision_json(&PendingDecision {
                    kind: PendingDecisionKind::ActionInstance.into(),
                    namespace: instance.namespace,
                    subject_id: instance.instance_id,
                    subject_digest: instance.request_digest,
                    requested_by: instance.principal,
                    requested_at_ms: instance.created_at_ms,
                    deadline_ms: instance.review_sla_deadline_ms,
                    queue_id: instance.review_queue_id,
                    dataset_id: String::new(),
                }))
                .collect::<Vec<_>>(),
            "next_page_token": "",
        })),
        Err(status) if status.code() == Code::Unimplemented => Ok(json!({ "unavailable": true })),
        Err(status) => Err(status.into()),
    }
}

fn decision_json(decision: &PendingDecision) -> Value {
    let kind = match decision.kind() {
        PendingDecisionKind::ActionInstance => "action_instance",
        PendingDecisionKind::PlanReview => "plan_review",
        PendingDecisionKind::DefinitionProposal => "definition_proposal",
        PendingDecisionKind::DatasetBranchProposal => "dataset_branch_proposal",
        PendingDecisionKind::Unspecified => "unspecified",
    };
    json!({
        "kind": kind,
        "namespace": decision.namespace,
        "subject_id": decision.subject_id,
        "subject_digest": decision.subject_digest,
        "requested_by": decision.requested_by,
        "requested_at_ms": decision.requested_at_ms,
        "deadline_ms": decision.deadline_ms,
        "queue_id": decision.queue_id,
        "dataset_id": decision.dataset_id,
    })
}

/// Chisei's open memory candidates, or `{unavailable: true}` when the plane
/// does not serve them; by default the maturity gate holds the RPC back.
/// The RPC takes at most 100 per page.
async fn memory_candidates(
    client: &mut ChiseiServiceClient<GatewayClient>,
    namespace: &str,
    limit: u32,
) -> Result<Value, BoxErr> {
    match client
        .list_kioku_candidates(ListKiokuCandidatesRequest {
            namespace: namespace.into(),
            operation_class: String::new(),
            limit: limit.min(100),
            page_token: String::new(),
        })
        .await
    {
        Ok(response) => Ok(response
            .into_inner()
            .candidates
            .into_iter()
            .map(|candidate| serde_json::from_str::<Value>(&candidate.memory_json))
            .collect::<Result<Vec<_>, _>>()?
            .into()),
        Err(status) if unserved(&status) => Ok(json!({ "unavailable": true })),
        Err(status) => Err(status.into()),
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::sekai::sekai_service_server::{SekaiService, SekaiServiceServer};
    use crate::grpc::pb::sekai::{ActionInstance, ListActionInstancesResponse};
    use tonic::{Request, Response, Status};

    /// An old plane: it has `ListActionInstances` and no
    /// `ListPendingDecisions`, and no Chisei service.
    struct OldPlane;

    #[tonic::async_trait]
    impl SekaiService for OldPlane {
        async fn list_action_instances(
            &self,
            request: Request<ListActionInstancesRequest>,
        ) -> Result<Response<ListActionInstancesResponse>, Status> {
            assert!(request.get_ref().decidable_by_caller);
            Ok(Response::new(ListActionInstancesResponse {
                instances: vec![ActionInstance {
                    instance_id: "parked-1".into(),
                    namespace: request.into_inner().namespace,
                    principal: "agent".into(),
                    created_at_ms: 7,
                    review_queue_id: "risk".into(),
                    ..Default::default()
                }],
            }))
        }
    }

    #[tokio::test]
    async fn an_old_sekai_plane_falls_back_and_chisei_reports_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(SekaiServiceServer::new(OldPlane))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        let channel = connect_sekai(&format!("http://{address}")).await.unwrap();

        let sekai = sekai_decisions(&mut SekaiServiceClient::new(channel.clone()), "acme", 10)
            .await
            .unwrap();
        assert_eq!(sekai["source"], "ListActionInstances");
        let decisions = sekai["decisions"].as_array().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["kind"], "action_instance");
        assert_eq!(decisions[0]["subject_id"], "parked-1");
        assert_eq!(decisions[0]["queue_id"], "risk");

        let chisei = memory_candidates(&mut ChiseiServiceClient::new(channel), "acme", 10)
            .await
            .unwrap();
        assert_eq!(chisei, json!({ "unavailable": true }));
        server.abort();
    }
}
