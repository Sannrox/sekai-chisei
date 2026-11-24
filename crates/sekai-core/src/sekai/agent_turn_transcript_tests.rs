use super::*;
use crate::sekai::agent_turn::{Cause, Wake, admit, claim};
use crate::sekai::retention::SubjectErasureRequest;
use std::collections::HashMap;

fn seed(db: &RuntimeDb, ns: &str, name: &str) -> String {
    let id = format!("{ns}-{name}");
    db.create_object(&crate::domain::Object {
        id: id.clone(),
        kind: crate::sekai::site_agent_instance::KIND.into(),
        name: name.into(),
        namespace: ns.into(),
        external_id: String::new(),
        properties: HashMap::from([("principal_id".to_string(), format!("agent:{id}"))]),
        created: 1,
        updated: 1,
    })
    .unwrap();
    id
}

fn claimed(db: &RuntimeDb, ns: &str, instance: &str, cause: Cause, cause_ref: &str) -> AgentTurn {
    claimed_by(db, ns, instance, cause, cause_ref, "alice")
}

fn claimed_by(
    db: &RuntimeDb,
    ns: &str,
    instance: &str,
    cause: Cause,
    cause_ref: &str,
    requester: &str,
) -> AgentTurn {
    let wake = Wake {
        namespace: ns.into(),
        instance_id: instance.into(),
        cause,
        cause_ref: cause_ref.into(),
        due_at_ms: 100,
    };
    let turn = admit(db, wake, requester, 1).unwrap();
    claim(db, ns, "worker", &turn.turn_id, 60_000, 200).unwrap()
}

fn step(id: &str) -> StepRecord {
    StepRecord {
        step_id: id.into(),
        kind: StepKind::ToolCall,
        name: "search".into(),
        target: "catalog".into(),
        action_instance_id: String::new(),
    }
}

fn append_to(
    db: &RuntimeDb,
    turn: &AgentTurn,
    append: TranscriptAppend,
) -> Result<TurnTranscript, TurnError> {
    super::append(
        db,
        &turn.turn_id,
        &turn.claim_owner,
        turn.claim_generation,
        &turn.fencing_token,
        append,
        300,
    )
}

fn erase(db: &RuntimeDb, kind: &str, subject: &str) {
    db.erase_subject(&SubjectErasureRequest {
        subject_kind: kind.into(),
        subject: subject.into(),
        requested_by: "dpo".into(),
        reason: "request".into(),
        timestamp: 500,
    })
    .unwrap();
}

fn with_step(id: &str) -> TranscriptAppend {
    TranscriptAppend {
        step: Some(step(id)),
        ..Default::default()
    }
}

fn prompt(text: &str) -> TranscriptAppend {
    TranscriptAppend {
        prompt: Some(PromptRecord {
            reference: "prompt://turn/1".into(),
            marking: "confidential".into(),
            text: Some(text.into()),
        }),
        ..Default::default()
    }
}

/// The transcript contract on one store.
fn transcript_contract(db: &RuntimeDb, ns: &str) {
    let instance = seed(db, ns, "line");
    let turn = claimed(db, ns, &instance, Cause::Schedule, "100");

    // A retried step is one step; the same id with other content is refused.
    append_to(db, &turn, with_step("s1")).unwrap();
    let again = append_to(db, &turn, with_step("s1")).unwrap();
    assert_eq!(again.steps.len(), 1);
    let mut changed = with_step("s1");
    changed.step.as_mut().unwrap().name = "other".into();
    assert!(matches!(
        append_to(db, &turn, changed),
        Err(TurnError::Invalid(_))
    ));

    // Usage is the latest report; the prompt is recorded once.
    let usage = TurnUsage {
        model_route: "local/model-a".into(),
        input_tokens: 120,
        output_tokens: 30,
    };
    append_to(
        db,
        &turn,
        TranscriptAppend {
            usage: Some(usage.clone()),
            ..prompt("Summarize the ticket.")
        },
    )
    .unwrap();
    append_to(db, &turn, prompt("Summarize the ticket.")).unwrap();
    assert!(matches!(
        append_to(db, &turn, prompt("Something else.")),
        Err(TurnError::Invalid(_))
    ));
    let stored = get(db, &turn.turn_id).unwrap();
    assert_eq!(stored.usage, Some(usage));
    assert_eq!(stored.prompt_marking, "confidential");
    assert!(stored.prompt_text_stored);
    assert_eq!(
        prompt_text(db, &turn.turn_id).unwrap().as_deref(),
        Some("Summarize the ticket.")
    );

    // A superseded fence and a lapsed claim cannot append.
    let stale = super::append(
        db,
        &turn.turn_id,
        &turn.claim_owner,
        turn.claim_generation,
        "not-the-token",
        with_step("s2"),
        300,
    );
    assert_eq!(stale, Err(TurnError::StaleClaim));
    let lapsed = super::append(
        db,
        &turn.turn_id,
        &turn.claim_owner,
        turn.claim_generation,
        &turn.fencing_token,
        with_step("s2"),
        10_000_000,
    );
    assert_eq!(lapsed, Err(TurnError::StaleClaim));
    assert_eq!(get(db, &turn.turn_id).unwrap().steps.len(), 1);

    // Erasure of a user the prompt names removes its text and refuses later
    // appends; the turn and its steps remain.
    let named = seed(db, ns, "named");
    let mentioning = claimed(db, ns, &named, Cause::Schedule, "100");
    let subject = format!("bob-{ns}");
    append_to(db, &mentioning, with_step("s1")).unwrap();
    append_to(
        db,
        &mentioning,
        prompt(&format!("Reply to user:{subject} today")),
    )
    .unwrap();
    erase(db, "user", &subject);
    let after = get(db, &mentioning.turn_id).unwrap();
    assert!(after.erased_at_ms > 0);
    assert!(!after.prompt_text_stored);
    assert_eq!(after.steps.len(), 1);
    assert_eq!(prompt_text(db, &mentioning.turn_id).unwrap(), None);
    assert!(matches!(
        append_to(db, &mentioning, with_step("s2")),
        Err(TurnError::Invalid(_))
    ));
    // The first turn's prompt does not name the subject and is kept.
    assert!(prompt_text(db, &turn.turn_id).unwrap().is_some());

    // A turn of another instance, with no transcript, is untouched.
    let other = seed(db, ns, "other");
    let untouched = claimed(db, ns, &other, Cause::Schedule, "100");
    append_to(db, &untouched, with_step("s1")).unwrap();
}

#[test]
fn bounds_refuse_instead_of_truncating() {
    let db = RuntimeDb::memory();
    let instance = seed(&db, "site", "line");
    let turn = claimed(&db, "site", &instance, Cause::Manual, "req-1");
    let long = "x".repeat(MAX_PROMPT_TEXT_BYTES + 1);
    assert!(matches!(
        append_to(&db, &turn, prompt(&long)),
        Err(TurnError::Invalid(_))
    ));
    for index in 0..MAX_TRANSCRIPT_STEPS {
        append_to(&db, &turn, with_step(&format!("s{index}"))).unwrap();
    }
    assert!(matches!(
        append_to(&db, &turn, with_step("one-more")),
        Err(TurnError::Invalid(_))
    ));
    let mut unmarked = prompt("text");
    unmarked.prompt.as_mut().unwrap().marking = String::new();
    assert!(matches!(
        append_to(&db, &turn, unmarked),
        Err(TurnError::Invalid(_))
    ));
}

/// Erasing the instance's agent or a manual turn's requester reaches the
/// turn by identity on both stores. The identity columns are a retained
/// identity (#3444), so they keep the subject and never block the erasure.
fn turn_identity_erasure_contract(db: &RuntimeDb, ns: &str) {
    let instance = seed(db, ns, "line");
    let requester = format!("carol-{ns}");
    let manual = claimed_by(db, ns, &instance, Cause::Manual, "req-1", &requester);
    let scheduled = claimed_by(db, ns, &instance, Cause::Schedule, "100", &requester);
    erase(db, "user", &requester);
    assert!(get(db, &manual.turn_id).unwrap().erased_at_ms > 0);
    assert_eq!(get(db, &scheduled.turn_id).unwrap().erased_at_ms, 0);
    erase(db, "agent", &scheduled.principal_id);
    assert!(get(db, &scheduled.turn_id).unwrap().erased_at_ms > 0);
}

#[test]
fn erasure_reaches_turns_by_their_agent_and_requester() {
    turn_identity_erasure_contract(&RuntimeDb::memory(), "site");
}

#[test]
fn sqlite_transcripts_follow_the_contract() {
    transcript_contract(&RuntimeDb::memory(), "site");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
fn postgres_transcripts_follow_the_contract() {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
    let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
            &url,
            4,
            &std::fs::read(path).unwrap(),
        ),
        Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
    };
    let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
    let ns = format!("transcript-{}-{}", std::process::id(), uuid::Uuid::new_v4());
    transcript_contract(&db, &ns);
    let ns = format!(
        "turn-identity-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    turn_identity_erasure_contract(&db, &ns);
}
