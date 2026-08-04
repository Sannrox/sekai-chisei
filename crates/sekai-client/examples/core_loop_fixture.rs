use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use futures_util::stream;
use sekai_client::{CallOptions, ClientConfig, CoreLoopClient, CoreLoopTransport};
use sekai_proto::chisei::{
    ExecutePlanRequest, ExecutePlanStreamEvent, ExecutionInput, ExecutionPlan,
    GetOperationReceiptRequest, GetOperationReceiptResponse, PlanExecutionRequest,
    PlanExecutionResponse, ReportOperationEventRequest, ReportOperationEventResponse,
};
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct DeterministicFixture;

#[async_trait]
impl CoreLoopTransport for DeterministicFixture {
    type Stream = Pin<Box<dyn Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;

    async fn plan_execution(
        &self,
        request: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        let input = request.into_inner().input.unwrap_or_default();
        Ok(Response::new(PlanExecutionResponse {
            plan: Some(ExecutionPlan {
                plan_id: "fixture-plan".into(),
                input: Some(input),
                executable: true,
                ..Default::default()
            }),
        }))
    }

    async fn execute_plan_stream(
        &self,
        _request: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::Stream>, Status> {
        Ok(Response::new(Box::pin(stream::iter([
            Ok(ExecutePlanStreamEvent {
                content_delta: "fixture".into(),
                ..Default::default()
            }),
            Ok(ExecutePlanStreamEvent {
                content_delta: " complete".into(),
                done: true,
                ..Default::default()
            }),
        ]))))
    }

    async fn report_operation_event(
        &self,
        request: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status> {
        let event_id = request.into_inner().event_id;
        Ok(Response::new(ReportOperationEventResponse {
            event_id,
            recorded: true,
            complete: true,
            ..Default::default()
        }))
    }

    async fn get_operation_receipt(
        &self,
        request: Request<GetOperationReceiptRequest>,
    ) -> Result<Response<GetOperationReceiptResponse>, Status> {
        let operation_id = request.into_inner().operation_id;
        Ok(Response::new(GetOperationReceiptResponse {
            receipt_json: format!("{{\"operation_id\":\"{operation_id}\"}}"),
            complete: true,
            ..Default::default()
        }))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = CoreLoopClient::new(
        ClientConfig::for_injected("fixture-host").with_namespace("demo"),
        DeterministicFixture,
    )?;
    let result = client
        .run_core_loop(
            ExecutionInput {
                namespace: "demo".into(),
                spec: "summarize the fixture".into(),
                ..Default::default()
            },
            CallOptions::new()
                .with_operation_id("fixture-operation")
                .with_request_id("fixture-request"),
        )
        .await?;
    client
        .report_operation_event(
            ReportOperationEventRequest {
                operation_id: result.plan.plan_id.clone(),
                event_id: "fixture-event".into(),
                kind: "outcome".into(),
                ..Default::default()
            },
            CallOptions::new().with_request_id("fixture-event-request"),
        )
        .await?;
    println!(
        "plan={} events={} receipt_complete={}",
        result.plan.plan_id,
        result.events.len(),
        result.receipt.complete
    );
    Ok(())
}
