//! Combined-mode worker that investigates new feedback observations (#1231).
//!
//! Polls plane-owned object-change bindings, claims one fenced dispatch, and
//! records structured investigation objects. Analysis uses PlanExecution and
//! ExecutePlanStream with no agent tools. Qualifying findings are published
//! by the GitHub worker (#1232).

use super::chisei_service::ChiseiServiceImpl;
use super::pb::chisei::chisei_service_server::ChiseiService;
use super::pb::chisei::{ChatMessage, ExecutePlanRequest, ExecutionInput, PlanExecutionRequest};
use super::pb::sekai::RunActionBindingRequest;
use super::pb::sekai::sekai_service_server::SekaiService;
use super::sekai_service::SekaiServiceImpl;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_effect::{ACK_OUTCOME_COMPLETED, ACK_OUTCOME_FAILED};
use crate::sekai::feedback_investigation::{
    AnalysisError, AnalysisRequest, Attribution, InvestigateError, InvestigationAnalysis,
    ObservationCluster, POLL_INTERVAL_SECS, RUNTIME_ID, ack_investigation, analysis_prompt,
    analysis_system_prompt, claim_next_dispatch, empty_analysis, gather_cluster,
    investigation_bindings, parse_model_analysis_json, record_investigation,
};
use crate::sekai::feedback_package::PACKAGE_ID;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request, Status};

pub(super) fn spawn_feedback_investigation(
    db: Arc<RuntimeDb>,
    sekai: Arc<SekaiServiceImpl>,
    chisei: Arc<ChiseiServiceImpl>,
) {
    tracing::info!(
        interval_secs = POLL_INTERVAL_SECS,
        runtime = RUNTIME_ID,
        "feedback investigation worker enabled"
    );
    tokio::spawn(async move {
        let investigating = Mutex::new(());
        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if let Err(error) = drain_investigation_bindings(&db, &sekai).await {
                tracing::error!(%error, "feedback investigation bindings failed");
            }
            let Ok(_guard) = investigating.try_lock() else {
                continue;
            };
            if let Err(error) = investigate_next(&db, &chisei).await {
                tracing::error!(%error, "feedback investigation pass failed");
            }
        }
    });
}

async fn drain_investigation_bindings(
    db: &RuntimeDb,
    sekai: &SekaiServiceImpl,
) -> Result<(), String> {
    let namespaces = db.list_live_package_namespaces(PACKAGE_ID)?;
    for namespace in namespaces {
        let bindings = investigation_bindings(&db.list_action_bindings(&namespace)?);
        for binding in bindings {
            let request = match principal_request(
                &binding.run_as,
                RunActionBindingRequest {
                    namespace: binding.namespace.clone(),
                    binding_id: binding.binding_id.clone(),
                    limit: 32,
                },
            ) {
                Ok(request) => request,
                Err(status) => {
                    tracing::warn!(
                        namespace = %binding.namespace,
                        binding = %binding.binding_id,
                        error = %status,
                        "feedback investigation binding run_as is not valid metadata"
                    );
                    continue;
                }
            };
            if let Err(status) = sekai.run_action_binding(request).await {
                tracing::warn!(
                    namespace = %binding.namespace,
                    binding = %binding.binding_id,
                    error = %status,
                    "feedback investigation binding run skipped"
                );
            }
        }
    }
    Ok(())
}

async fn investigate_next(db: &Arc<RuntimeDb>, chisei: &ChiseiServiceImpl) -> Result<(), String> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let runtime = db.clone();
    let claimed = tokio::task::spawn_blocking(move || claim_any(&runtime, now_ms))
        .await
        .map_err(|error| error.to_string())??;
    let Some((claimed, cluster, actor)) = claimed else {
        return Ok(());
    };
    let request = AnalysisRequest {
        namespace: cluster.namespace.clone(),
        signature: cluster.signature.clone(),
        observations: cluster.observations.clone(),
    };
    let analysis = match analyze_with_plan(chisei, &actor, &request).await {
        Ok(analysis) => analysis,
        Err(AnalysisError::BudgetExhausted) => {
            ack_blocking(db, &claimed, &actor, ACK_OUTCOME_FAILED, "budget_exhausted").await?;
            return Ok(());
        }
        Err(AnalysisError::Malformed(_)) => InvestigationAnalysis {
            attribution: Attribution::Malformed,
            ..empty_analysis()
        },
        Err(AnalysisError::Unavailable(_)) => InvestigationAnalysis {
            attribution: Attribution::Inconclusive,
            ..empty_analysis()
        },
    };
    let runtime = db.clone();
    let claimed_for_write = claimed.clone();
    let actor_for_write = actor.clone();
    let write = tokio::task::spawn_blocking(move || {
        record_investigation(
            &runtime,
            &cluster,
            &analysis,
            &actor_for_write,
            chrono::Utc::now().timestamp_millis(),
        )?;
        ack_investigation(
            &runtime,
            &claimed_for_write,
            &actor_for_write,
            ACK_OUTCOME_COMPLETED,
            "",
            chrono::Utc::now().timestamp_millis(),
        )
    })
    .await
    .map_err(|error| error.to_string())?;
    match write {
        Ok(()) => Ok(()),
        Err(InvestigateError::BudgetExhausted) => {
            ack_blocking(db, &claimed, &actor, ACK_OUTCOME_FAILED, "budget_exhausted").await
        }
        Err(error) => {
            let _ = ack_blocking(
                db,
                &claimed,
                &actor,
                ACK_OUTCOME_FAILED,
                "investigation_failed",
            )
            .await;
            Err(format!("{error:?}"))
        }
    }
}

fn claim_any(
    db: &RuntimeDb,
    now_ms: i64,
) -> Result<
    Option<(
        crate::sekai::action_work_lifecycle::ClaimedActionWork,
        ObservationCluster,
        String,
    )>,
    String,
> {
    for namespace in db.list_live_package_namespaces(PACKAGE_ID)? {
        let claimed = match claim_next_dispatch(db, &namespace, RUNTIME_ID, now_ms) {
            Ok(claimed) => claimed,
            Err(InvestigateError::Internal(error)) => return Err(error),
            Err(error) => return Err(format!("{error:?}")),
        };
        let Some(claimed) = claimed else {
            continue;
        };
        let instance = db
            .get_action_instance(&claimed.effect.instance_id)?
            .ok_or_else(|| "claimed investigation instance is gone".to_string())?;
        let cluster = gather_cluster(db, &namespace, &observation_id(&instance)?, now_ms)
            .map_err(|error| format!("{error:?}"))?;
        return Ok(Some((claimed, cluster, instance.principal)));
    }
    Ok(None)
}

fn observation_id(
    instance: &crate::sekai::action_instance::ActionInstance,
) -> Result<String, String> {
    let parameters: serde_json::Value =
        serde_json::from_str(&instance.parameters_json).map_err(|error| error.to_string())?;
    parameters
        .get("observation_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "dispatch is missing observation_id".into())
}

async fn analyze_with_plan(
    chisei: &ChiseiServiceImpl,
    actor: &str,
    request: &AnalysisRequest,
) -> Result<InvestigationAnalysis, AnalysisError> {
    let mut plan_request = Request::new(PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: format!(
                "feedback-inv-{}",
                request
                    .observations
                    .first()
                    .map(|o| o.object_id.as_str())
                    .unwrap_or("cluster")
            ),
            namespace: request.namespace.clone(),
            spec: analysis_prompt(request),
            user_id: actor.into(),
            estimated_tokens: 2_048,
            max_tokens: 1_024,
            messages: vec![ChatMessage {
                role: "user".into(),
                content: analysis_prompt(request),
                ..Default::default()
            }],
            system: analysis_system_prompt().into(),
            tools: Vec::new(),
            ..Default::default()
        }),
        gunshi_allocation: None,
        routing_profile_id: String::new(),
    });
    insert_principal(&mut plan_request, actor).map_err(status_to_analysis)?;
    let planned = chisei
        .plan_execution(plan_request)
        .await
        .map_err(status_to_analysis)?
        .into_inner()
        .plan
        .ok_or_else(|| AnalysisError::Unavailable("plan omitted".into()))?;
    if !planned.executable {
        return Err(AnalysisError::Unavailable("plan is not executable".into()));
    }
    let mut execute_request = Request::new(ExecutePlanRequest {
        plan: Some(planned),
    });
    insert_principal(&mut execute_request, actor).map_err(status_to_analysis)?;
    let executed = chisei
        .execute_plan(execute_request)
        .await
        .map_err(status_to_analysis)?
        .into_inner();
    let content = executed
        .response
        .as_ref()
        .map(|response| response.content.as_str())
        .unwrap_or("");
    parse_model_analysis_json(content)
}

fn status_to_analysis(status: Status) -> AnalysisError {
    if status.code() == Code::ResourceExhausted {
        AnalysisError::BudgetExhausted
    } else {
        AnalysisError::Unavailable(status.message().into())
    }
}

fn principal_request<T>(principal: &str, payload: T) -> Result<Request<T>, Status> {
    let mut request = Request::new(payload);
    insert_principal(&mut request, principal)?;
    Ok(request)
}

fn insert_principal<T>(request: &mut Request<T>, principal: &str) -> Result<(), Status> {
    let value = MetadataValue::try_from(principal)
        .map_err(|_| Status::internal("principal is not valid metadata"))?;
    request.metadata_mut().insert("x-principal", value);
    Ok(())
}

async fn ack_blocking(
    db: &Arc<RuntimeDb>,
    claimed: &crate::sekai::action_work_lifecycle::ClaimedActionWork,
    actor: &str,
    outcome: &'static str,
    reason: &'static str,
) -> Result<(), String> {
    let runtime = db.clone();
    let claimed = claimed.clone();
    let actor = actor.to_string();
    tokio::task::spawn_blocking(move || {
        ack_investigation(
            &runtime,
            &claimed,
            &actor,
            outcome,
            reason,
            chrono::Utc::now().timestamp_millis(),
        )
        .map_err(|error| format!("{error:?}"))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::feedback_investigation::POLL_INTERVAL_SECS;

    #[test]
    fn combined_worker_polls_every_15_seconds() {
        assert_eq!(POLL_INTERVAL_SECS, 15);
        assert_eq!(RUNTIME_ID, "feedback-investigation");
    }
}
