//! Agent-turn transcripts over gRPC (ADR 0157): fenced appends and the
//! clearance-gated prompt text on the instance turn list.

use super::*;
use crate::sekai::security::Role;
use tonic::metadata::MetadataValue;

const NS: &str = "ops";
const INSTANCE: &str = "line-7";
const AGENT: &str = "agent:line-7";

fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    req
}

/// A sealed profile giving `principal` the `ceiling` marking clearance.
fn clear(svc: &SekaiServiceImpl, principal: &str, ceiling: &str) {
    let id = format!("profile-{principal}");
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: id.clone(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: principal.into(),
            namespace: NS.into(),
            external_id: markings::principal_profile_external_id(principal),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    ceiling.into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    let grant = crate::sekai::security::Grant {
        id: format!("grant-{id}"),
        object_id: id,
        principal: "root".into(),
        role: Role::Admin,
        created: 0,
        ..Default::default()
    };
    svc.db.runtime().create_grant(&grant).unwrap();
    svc.security.add_grant(&grant);
}

/// A service with one instance whose agent is cleared for confidential,
/// a namespace viewer, and one claimed turn of that instance.
async fn claimed_turn() -> (SekaiServiceImpl, AgentTurn) {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    crate::chisei_store::apply_chisei_schema(&db);
    let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));
    let (_, grants) = svc
        .db
        .runtime()
        .ensure_team_namespace(NS, "reader", Role::Viewer, "local")
        .unwrap();
    for grant in grants {
        svc.security.add_grant(&grant);
    }
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: INSTANCE.into(),
            kind: crate::sekai::site_agent_instance::KIND.into(),
            name: "line 7".into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("principal_id".to_string(), AGENT.to_string()),
                ("frozen".to_string(), "false".to_string()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    clear(&svc, AGENT, "confidential");
    let woken = svc
        .wake_site_agent_instance(as_principal(
            WakeSiteAgentInstanceRequest {
                namespace: NS.into(),
                instance_id: INSTANCE.into(),
                request_id: "req-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap();
    let turn = svc
        .claim_agent_turn(as_principal(
            ClaimAgentTurnRequest {
                namespace: NS.into(),
                runtime_id: "runner-a".into(),
                turn_id: woken.turn_id,
                ttl_ms: 60_000,
                accepts_continuation: true,
                accepts_interactive: false,
            },
            "local",
        ))
        .await
        .unwrap()
        .into_inner()
        .turn
        .unwrap();
    (svc, turn)
}

fn append(turn: &AgentTurn) -> AppendAgentTurnTranscriptRequest {
    AppendAgentTurnTranscriptRequest {
        turn_id: turn.turn_id.clone(),
        runtime_id: turn.claim_owner.clone(),
        claim_generation: turn.claim_generation,
        fencing_token: turn.fencing_token.clone(),
        ..Default::default()
    }
}

fn tool_step(step_id: &str) -> AgentTurnStep {
    AgentTurnStep {
        step_id: step_id.into(),
        kind: "tool_call".into(),
        name: "search".into(),
        target: "catalog".into(),
        ..Default::default()
    }
}

fn prompt(marking: &str) -> AgentTurnPrompt {
    AgentTurnPrompt {
        reference: "template:reply@3".into(),
        marking: marking.into(),
        text: "Summarize the ticket.".into(),
    }
}

async fn send(
    svc: &SekaiServiceImpl,
    request: AppendAgentTurnTranscriptRequest,
) -> Result<AgentTurnTranscript, tonic::Code> {
    svc.append_agent_turn_transcript(as_principal(request, "local"))
        .await
        .map(|response| response.into_inner().transcript.unwrap())
        .map_err(|status| status.code())
}

async fn listed(
    svc: &SekaiServiceImpl,
    reader: &str,
    include_prompt_text: bool,
) -> AgentTurnTranscript {
    svc.list_site_agent_instance_turns(as_principal(
        ListSiteAgentInstanceTurnsRequest {
            namespace: NS.into(),
            instance_id: INSTANCE.into(),
            limit: 10,
            page_token: String::new(),
            include_prompt_text,
        },
        reader,
    ))
    .await
    .unwrap()
    .into_inner()
    .turns
    .remove(0)
    .transcript
    .unwrap()
}

#[tokio::test]
async fn appends_are_fenced_idempotent_and_within_the_agent_clearance() {
    let (svc, turn) = claimed_turn().await;
    let step = AppendAgentTurnTranscriptRequest {
        step: Some(tool_step("s1")),
        ..append(&turn)
    };
    send(&svc, step.clone()).await.unwrap();
    assert_eq!(send(&svc, step).await.unwrap().steps.len(), 1);

    // A superseded fence cannot append.
    let stale = AppendAgentTurnTranscriptRequest {
        fencing_token: "not-the-token".into(),
        step: Some(tool_step("s2")),
        ..append(&turn)
    };
    assert_eq!(
        send(&svc, stale).await,
        Err(tonic::Code::FailedPrecondition)
    );

    // A prompt above the agent's ceiling, or an unknown Action, is refused.
    let over = AppendAgentTurnTranscriptRequest {
        prompt: Some(prompt("restricted")),
        ..append(&turn)
    };
    assert_eq!(send(&svc, over).await, Err(tonic::Code::PermissionDenied));
    let unknown = AppendAgentTurnTranscriptRequest {
        step: Some(AgentTurnStep {
            kind: "action".into(),
            action_instance_id: "missing".into(),
            ..tool_step("s3")
        }),
        ..append(&turn)
    };
    assert_eq!(send(&svc, unknown).await, Err(tonic::Code::NotFound));

    // The append response never echoes prompt text.
    let recorded = send(
        &svc,
        AppendAgentTurnTranscriptRequest {
            prompt: Some(prompt("confidential")),
            usage: Some(AgentTurnUsage {
                model_route: "local/model-a".into(),
                input_tokens: 120,
                output_tokens: 30,
            }),
            ..append(&turn)
        },
    )
    .await
    .unwrap();
    assert!(recorded.prompt_text_stored);
    assert!(recorded.prompt_text.is_empty());
    assert_eq!(recorded.usage.unwrap().input_tokens, 120);
}

#[tokio::test]
async fn listed_prompt_text_needs_the_request_and_the_reader_clearance() {
    let (svc, turn) = claimed_turn().await;
    send(
        &svc,
        AppendAgentTurnTranscriptRequest {
            prompt: Some(prompt("confidential")),
            step: Some(tool_step("s1")),
            ..append(&turn)
        },
    )
    .await
    .unwrap();

    // An uncleared reader sees the reference and steps, not the text.
    let uncleared = listed(&svc, "reader", true).await;
    assert_eq!(uncleared.prompt_reference, "template:reply@3");
    assert_eq!(uncleared.steps.len(), 1);
    assert!(uncleared.prompt_text.is_empty());
    assert!(uncleared.prompt_text_withheld);

    // A cleared reader gets it only when asking.
    clear(&svc, "reader", "confidential");
    assert!(listed(&svc, "reader", false).await.prompt_text_withheld);
    assert_eq!(
        listed(&svc, "reader", true).await.prompt_text,
        "Summarize the ticket."
    );

    // After erasure of a subject the prompt names, nothing is returned and
    // the transcript refuses appends.
    svc.db
        .runtime()
        .erase_subject(&crate::sekai::retention::SubjectErasureRequest {
            subject_kind: "agent".into(),
            subject: AGENT.into(),
            requested_by: "dpo".into(),
            reason: "request".into(),
            timestamp: 500,
        })
        .unwrap();
    let erased = listed(&svc, "reader", true).await;
    assert!(erased.erased_at_ms > 0);
    assert!(!erased.prompt_text_stored && !erased.prompt_text_withheld);
    let later = AppendAgentTurnTranscriptRequest {
        step: Some(tool_step("s2")),
        ..append(&turn)
    };
    assert_eq!(send(&svc, later).await, Err(tonic::Code::InvalidArgument));
}
