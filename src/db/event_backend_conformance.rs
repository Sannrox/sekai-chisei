//! Shared SQLite/PostgreSQL event-stream and subscription matrix (#822).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Barrier};
use std::thread;

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::event_stream::{
    BATCH_GAP, BATCH_LATE, BATCH_MALFORMED, CHECKPOINT_CONFLICT, EVENT_STREAM_CONTRACT,
    EventStreamBatch, EventStreamBinding, EventStreamCheckpoint, EventStreamColumn,
    PROJECT_UNAVAILABLE, REVISION_UNSUPPORTED, SCHEMA_REVISION_V1, StreamEvent, batch_digest_for,
    project_event_batch, register_event_stream,
};
use crate::sekai::event_subscription::{
    CURSOR_CONFLICT, EVENT_SUBSCRIPTION_CONTRACT, EventSubscription, EventSubscriptionCursor,
    EventSubscriptionPage, PAGE_GAP, PAGE_LATE, PAGE_MALFORMED, RETENTION_GAP,
    SCHEMA_REVISION_V1 as SUB_REVISION, STATUS_REVOKED, SUBSCRIBE_UNAVAILABLE,
    deliver_subscription_page, inspect_event_subscription, page_digest_for,
    register_event_subscription, revoke_event_subscription,
};
use crate::sekai::markings::{
    PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY, PRINCIPAL_PROFILE_KIND,
    PRINCIPAL_PROFILE_SEALED_PROPERTY, principal_profile_external_id,
};
use crate::sekai::security::{Grant, Role};

struct Case {
    stream_id: String,
    namespace: String,
    principal: String,
    subscription_id: String,
}

impl Case {
    fn new(scope: &str) -> Self {
        Self {
            stream_id: format!("github:{scope}"),
            namespace: scope.into(),
            principal: format!("analyst-{scope}"),
            subscription_id: format!("{scope}-alerts"),
        }
    }
}

fn pin_ceiling(runtime: &RuntimeDb, case: &Case, ceiling: &str) {
    let profile_id = format!("profile:{}", case.principal);
    runtime
        .create_object(&Object {
            id: profile_id.clone(),
            kind: PRINCIPAL_PROFILE_KIND.into(),
            name: case.principal.clone(),
            namespace: case.namespace.clone(),
            external_id: principal_profile_external_id(&case.principal),
            properties: HashMap::from([
                (
                    PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    ceiling.into(),
                ),
                (PRINCIPAL_PROFILE_SEALED_PROPERTY.into(), "true".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    runtime
        .create_grant(&Grant {
            id: format!("grant:{}", case.principal),
            object_id: profile_id,
            principal: "root".into(),
            role: Role::Admin,
            created: 1,
        })
        .unwrap();
}

fn binding(case: &Case) -> EventStreamBinding {
    EventStreamBinding {
        contract_version: EVENT_STREAM_CONTRACT.into(),
        stream_id: case.stream_id.clone(),
        namespace: case.namespace.clone(),
        owner: case.principal.clone(),
        source: "github".into(),
        source_instance: "sekai/chisei".into(),
        schema_revision: SCHEMA_REVISION_V1.into(),
        type_digest: "sha256:typedef".into(),
        definition_digest: String::new(),
        columns: vec![
            EventStreamColumn {
                name: "id".into(),
                col_type: "int".into(),
                classification: "public".into(),
            },
            EventStreamColumn {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            },
            EventStreamColumn {
                name: "secret".into(),
                col_type: "string".into(),
                classification: "restricted".into(),
            },
        ],
        registered_by: String::new(),
        registered_at_ms: 0,
    }
}

fn event(offset: u64) -> StreamEvent {
    StreamEvent {
        offset,
        event_id: format!("e{offset}"),
        properties: BTreeMap::from([
            ("id".into(), offset.to_string()),
            ("kind".into(), "issue".into()),
            ("secret".into(), "hidden".into()),
        ]),
    }
}

fn batch(case: &Case, start: u64, end: u64) -> EventStreamBatch {
    let events: Vec<_> = (start..=end).map(event).collect();
    let mut batch = EventStreamBatch {
        stream_id: case.stream_id.clone(),
        generation: 1,
        feed_epoch: "epoch-1".into(),
        offset_start: start,
        offset_end: end,
        events,
        content_digest: String::new(),
    };
    batch.content_digest = batch_digest_for(&batch).unwrap();
    batch
}

fn page(case: &Case, start: u64, end: u64) -> EventSubscriptionPage {
    let events: Vec<_> = (start..=end).map(event).collect();
    let mut page = EventSubscriptionPage {
        subscription_id: case.subscription_id.clone(),
        namespace: case.namespace.clone(),
        stream_id: case.stream_id.clone(),
        generation: 1,
        feed_epoch: "epoch-1".into(),
        offset_start: start,
        offset_end: end,
        events,
        content_digest: String::new(),
    };
    page.content_digest = page_digest_for(&page).unwrap();
    page
}

fn subscription(case: &Case) -> EventSubscription {
    EventSubscription {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: case.subscription_id.clone(),
        namespace: case.namespace.clone(),
        owner: case.principal.clone(),
        stream_id: case.stream_id.clone(),
        schema_revision: SUB_REVISION.into(),
        type_digest: String::new(),
        definition_digest: String::new(),
        columns: vec!["id".into(), "kind".into()],
        retention_ms: 10_000,
        status: String::new(),
        cursor: EventSubscriptionCursor {
            generation: 0,
            feed_epoch: String::new(),
            committed_offset: 0,
            last_page_digest: String::new(),
            admitted_at_ms: 0,
        },
        registered_by: String::new(),
        registered_at_ms: 0,
    }
}

fn setup_stream(runtime: &RuntimeDb, case: &Case) {
    pin_ceiling(runtime, case, "internal");
    register_event_stream(runtime, &case.principal, &binding(case), 1_000).unwrap();
}

fn setup_subscription(runtime: &RuntimeDb, case: &Case) {
    setup_stream(runtime, case);
    project_event_batch(runtime, &case.principal, &batch(case, 1, 2), 2_000).unwrap();
    register_event_subscription(runtime, &case.principal, &subscription(case), 3_000).unwrap();
}

fn assert_projection_matrix(runtime: &RuntimeDb, case: &Case) {
    setup_stream(runtime, case);
    let first = project_event_batch(runtime, &case.principal, &batch(case, 1, 2), 2_000).unwrap();
    assert_eq!(first.outcome, "accepted");
    assert_eq!(first.checkpoint.committed_offset, 2);
    assert!(
        first
            .events
            .iter()
            .all(|event| !event.properties.contains_key("secret"))
    );
    let replay = project_event_batch(runtime, &case.principal, &batch(case, 1, 2), 3_000).unwrap();
    assert_eq!(replay.outcome, "replayed");
    assert_eq!(replay.checkpoint.committed_offset, 2);
    assert_eq!(replay.projection_digest, first.projection_digest);

    assert_eq!(
        project_event_batch(runtime, &case.principal, &batch(case, 4, 4), 4_000).unwrap_err(),
        BATCH_GAP
    );
    let mut late = batch(case, 1, 2);
    late.events[0].event_id = "other".into();
    late.content_digest = batch_digest_for(&late).unwrap();
    assert_eq!(
        project_event_batch(runtime, &case.principal, &late, 4_100).unwrap_err(),
        BATCH_LATE
    );
    let mut malformed = batch(case, 3, 3);
    malformed.events[0].offset = 9;
    malformed.content_digest = batch_digest_for(&malformed).unwrap();
    assert_eq!(
        project_event_batch(runtime, &case.principal, &malformed, 4_200).unwrap_err(),
        BATCH_MALFORMED
    );
    assert_eq!(
        project_event_batch(runtime, "intruder", &batch(case, 4, 4), 4_300).unwrap_err(),
        PROJECT_UNAVAILABLE
    );
    let mut bad = binding(case);
    bad.stream_id = format!("{}-v2", case.stream_id);
    bad.schema_revision = "v2".into();
    assert_eq!(
        register_event_stream(runtime, &case.principal, &bad, 4_400).unwrap_err(),
        REVISION_UNSUPPORTED
    );

    let mut next = binding(case);
    next.type_digest = "sha256:other".into();
    register_event_stream(runtime, &case.principal, &next, 5_000).unwrap();
    assert_eq!(
        runtime
            .get_event_stream_checkpoint(&case.stream_id)
            .unwrap(),
        None
    );
    let restart = project_event_batch(runtime, &case.principal, &batch(case, 1, 1), 5_100).unwrap();
    assert_eq!(restart.outcome, "accepted");
    let stale = EventStreamCheckpoint {
        stream_id: case.stream_id.clone(),
        generation: 1,
        feed_epoch: "epoch-1".into(),
        committed_offset: 0,
        last_batch_digest: String::new(),
    };
    let attempted = EventStreamCheckpoint {
        stream_id: case.stream_id.clone(),
        generation: 1,
        feed_epoch: "epoch-1".into(),
        committed_offset: 2,
        last_batch_digest: "sha256:stale".into(),
    };
    assert_eq!(
        runtime
            .advance_event_stream_checkpoint(
                &attempted,
                &stale,
                &runtime
                    .get_event_stream_binding(&case.stream_id)
                    .unwrap()
                    .unwrap()
                    .definition_digest,
                None,
            )
            .unwrap_err(),
        CHECKPOINT_CONFLICT
    );
}

fn assert_subscription_matrix(runtime: &RuntimeDb, case: &Case) {
    setup_subscription(runtime, case);
    let first =
        deliver_subscription_page(runtime, &case.principal, &page(case, 1, 1), 4_000).unwrap();
    assert_eq!(first.outcome, "accepted");
    assert_eq!(first.cursor.committed_offset, 1);
    assert!(
        first
            .events
            .iter()
            .all(|event| !event.properties.contains_key("secret"))
    );
    let replay =
        deliver_subscription_page(runtime, &case.principal, &page(case, 1, 1), 4_100).unwrap();
    assert_eq!(replay.outcome, "replayed");
    let restarted =
        register_event_subscription(runtime, &case.principal, &subscription(case), 4_200).unwrap();
    assert_eq!(restarted.cursor.committed_offset, 1);
    let next =
        deliver_subscription_page(runtime, &case.principal, &page(case, 2, 2), 4_300).unwrap();
    assert_eq!(next.outcome, "accepted");

    assert_eq!(
        deliver_subscription_page(runtime, &case.principal, &page(case, 3, 3), 4_400).unwrap_err(),
        PAGE_GAP
    );
    let mut fabricated = page(case, 1, 2);
    fabricated.events[0].event_id = "other".into();
    fabricated.content_digest = page_digest_for(&fabricated).unwrap();
    assert_eq!(
        deliver_subscription_page(runtime, &case.principal, &fabricated, 4_500).unwrap_err(),
        PAGE_MALFORMED
    );
    assert_eq!(
        deliver_subscription_page(runtime, &case.principal, &page(case, 1, 1), 4_550).unwrap_err(),
        PAGE_LATE
    );

    assert_eq!(
        deliver_subscription_page(runtime, &case.principal, &page(case, 2, 2), 20_000).unwrap_err(),
        RETENTION_GAP
    );
    let recovered =
        register_event_subscription(runtime, &case.principal, &subscription(case), 20_200).unwrap();
    assert_eq!(recovered.cursor.committed_offset, 0);
    assert_eq!(
        deliver_subscription_page(runtime, &case.principal, &page(case, 1, 1), 20_300)
            .unwrap()
            .outcome,
        "accepted"
    );
    let revoked = revoke_event_subscription(
        runtime,
        &case.principal,
        &case.namespace,
        &case.subscription_id,
        21_000,
    )
    .unwrap();
    assert_eq!(revoked.status, STATUS_REVOKED);
    assert_eq!(
        deliver_subscription_page(runtime, &case.principal, &page(case, 1, 1), 21_100).unwrap_err(),
        SUBSCRIBE_UNAVAILABLE
    );
    assert_eq!(
        inspect_event_subscription(runtime, "intruder", &case.namespace, &case.subscription_id)
            .unwrap_err(),
        SUBSCRIBE_UNAVAILABLE
    );
}

fn postgres_runtime() -> RuntimeDb {
    let database_url = std::env::var("SEKAI_TEST_POSTGRES_URL").unwrap_or_else(|_| {
        panic!("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database")
    });
    let db = if let Ok(ca_certificate_path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        let ca_certificate = std::fs::read(&ca_certificate_path).unwrap_or_else(|error| {
            panic!("read PostgreSQL test CA certificate {ca_certificate_path}: {error}")
        });
        PostgresDb::connect_with_ca_certificate(&database_url, 4, &ca_certificate).unwrap()
    } else {
        PostgresDb::connect(&database_url, 4).unwrap()
    };
    RuntimeDb::Postgres(Arc::new(db))
}

#[test]
fn sqlite_event_projection_and_subscription_matrix() {
    let projection = RuntimeDb::memory();
    assert_projection_matrix(&projection, &Case::new("sqlite-proj"));
    let subscription = RuntimeDb::memory();
    assert_subscription_matrix(&subscription, &Case::new("sqlite-sub"));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_event_projection_and_subscription_matrix() {
    let runtime = postgres_runtime();
    assert_projection_matrix(&runtime, &Case::new("pg-proj"));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_event_subscription_matrix() {
    let runtime = postgres_runtime();
    assert_subscription_matrix(&runtime, &Case::new("pg-sub"));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_checkpoint_and_cursor_races() {
    let case = Case::new("pg-race");
    let runtime = Arc::new(postgres_runtime());
    setup_stream(&runtime, &case);
    project_event_batch(&runtime, &case.principal, &batch(&case, 1, 1), 2_000).unwrap();
    let expected = runtime
        .get_event_stream_checkpoint(&case.stream_id)
        .unwrap()
        .unwrap();
    let digest = runtime
        .get_event_stream_binding(&case.stream_id)
        .unwrap()
        .unwrap()
        .definition_digest;
    let first = EventStreamCheckpoint {
        stream_id: case.stream_id.clone(),
        generation: 1,
        feed_epoch: "epoch-1".into(),
        committed_offset: 2,
        last_batch_digest: "sha256:one".into(),
    };
    let second = EventStreamCheckpoint {
        stream_id: case.stream_id.clone(),
        generation: 1,
        feed_epoch: "epoch-1".into(),
        committed_offset: 3,
        last_batch_digest: "sha256:two".into(),
    };
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = [first, second]
        .into_iter()
        .map(|next| {
            let runtime = Arc::clone(&runtime);
            let expected = expected.clone();
            let digest = digest.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                runtime.advance_event_stream_checkpoint(&next, &expected, &digest, None)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let ok = results.iter().filter(|result| result.is_ok()).count();
    let conflict = results
        .iter()
        .filter(|result| result.as_ref().err() == Some(&CHECKPOINT_CONFLICT.to_string()))
        .count();
    assert_eq!(ok, 1);
    assert_eq!(conflict, 1);

    register_event_subscription(&runtime, &case.principal, &subscription(&case), 3_000).unwrap();
    deliver_subscription_page(&runtime, &case.principal, &page(&case, 1, 1), 4_000).unwrap();
    let current = inspect_event_subscription(
        &runtime,
        &case.principal,
        &case.namespace,
        &case.subscription_id,
    )
    .unwrap();
    let mut left = current.clone();
    left.cursor.committed_offset = 2;
    left.cursor.last_page_digest = "sha256:left".into();
    let mut right = current.clone();
    right.cursor.committed_offset = 2;
    right.cursor.last_page_digest = "sha256:right".into();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = [left, right]
        .into_iter()
        .map(|next| {
            let runtime = Arc::clone(&runtime);
            let expected = current.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                runtime.advance_event_subscription_cursor(&next, &expected)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let ok = results.iter().filter(|result| result.is_ok()).count();
    let conflict = results
        .iter()
        .filter(|result| result.as_ref().err() == Some(&CURSOR_CONFLICT.to_string()))
        .count();
    assert_eq!(ok, 1);
    assert_eq!(conflict, 1);
}
