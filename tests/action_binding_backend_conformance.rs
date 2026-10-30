//! Object-change Action bindings behave the same on SQLite and PostgreSQL
//! (#1319): each install gets the next revision and restarts delivery, the
//! cursor round-trips with its pending events and read marker, and a cursor
//! write for a superseded revision changes nothing.

use std::collections::BTreeMap;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::action_binding::{
    ACTION_BINDING_CONTRACT, ActionBinding, ActionBindingCursor, ParameterSource, ReadMarker,
};
use sekai_chisei::sekai::event_subscription::{EventSubscription, EventSubscriptionCursor};
use sekai_chisei::sekai::object_change_subscription::{OP_UPDATE, ObjectChangeEvent};

use crate::postgres_scratch::ScratchDatabase;

fn binding(namespace: &str) -> ActionBinding {
    ActionBinding {
        contract_version: ACTION_BINDING_CONTRACT.into(),
        binding_id: "escalate-on-update".into(),
        namespace: namespace.into(),
        kind: "incident".into(),
        property_filters: Vec::new(),
        ops: vec![OP_UPDATE.into()],
        type_id: "incident.escalate".into(),
        version: "1".into(),
        run_as: "svc-escalator".into(),
        parameters: BTreeMap::from([("object_id".into(), ParameterSource::ObjectId)]),
        markings: Vec::new(),
        enabled: true,
        revision: 0,
        created_by: String::new(),
        updated_at_ms: 0,
    }
}

fn subscription(namespace: &str) -> EventSubscription {
    EventSubscription {
        contract_version: "sekai.event-subscription/v1".into(),
        subscription_id: "action-binding.escalate-on-update".into(),
        namespace: namespace.into(),
        owner: "svc".into(),
        stream_id: "stream-1".into(),
        schema_revision: "1".into(),
        type_digest: "sha256:type".into(),
        definition_digest: "sha256:definition".into(),
        columns: Vec::new(),
        retention_ms: 0,
        status: "active".into(),
        cursor: EventSubscriptionCursor {
            generation: 1,
            feed_epoch: "epoch".into(),
            committed_offset: 7,
            last_page_digest: "sha256:page".into(),
            admitted_at_ms: 1,
        },
        registered_by: "svc".into(),
        registered_at_ms: 1,
    }
}

fn exercise(db: &RuntimeDb, namespace: &str) {
    assert!(
        db.get_action_binding(namespace, "escalate-on-update")
            .unwrap()
            .is_none()
    );
    let first = db
        .put_action_binding(&binding(namespace), "admin", 10)
        .unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(first.created_by, "admin");
    let (stored, cursor) = db
        .get_action_binding(namespace, "escalate-on-update")
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, 1);
    assert_eq!(cursor, ActionBindingCursor::default());
    let listed = db.list_action_bindings(namespace).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].binding_id, "escalate-on-update");
    assert!(db.list_action_bindings("missing-ns").unwrap().is_empty());

    for read_marker in [
        Some(ReadMarker::Absent),
        Some(ReadMarker::Subscription(Box::new(subscription(namespace)))),
        None,
    ] {
        let cursor = ActionBindingCursor {
            snapshot_revision: "snap-1".into(),
            last_page_digest: "sha256:page".into(),
            pending_events: vec![ObjectChangeEvent {
                offset: 7,
                event_id: "evt-7".into(),
                object_id: "inc-1".into(),
                kind: "incident".into(),
                op: OP_UPDATE.into(),
                field: "severity".into(),
                committed_at_ms: 1,
                operation_id: "op".into(),
            }],
            read_marker,
        };
        db.advance_action_binding_cursor(&first, &cursor, 11)
            .unwrap();
        let (_, read) = db
            .get_action_binding(namespace, "escalate-on-update")
            .unwrap()
            .unwrap();
        assert_eq!(read, cursor);
    }

    // A reinstall takes the next revision and restarts delivery; the old
    // revision's cursor write then changes nothing.
    let second = db
        .put_action_binding(&binding(namespace), "admin", 12)
        .unwrap();
    assert_eq!(second.revision, 2);
    let (_, reset) = db
        .get_action_binding(namespace, "escalate-on-update")
        .unwrap()
        .unwrap();
    assert_eq!(reset, ActionBindingCursor::default());
    db.advance_action_binding_cursor(
        &first,
        &ActionBindingCursor {
            snapshot_revision: "stale".into(),
            ..ActionBindingCursor::default()
        },
        13,
    )
    .unwrap();
    let (current, kept) = db
        .get_action_binding(namespace, "escalate-on-update")
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, 2);
    assert_eq!(kept, ActionBindingCursor::default());

    // An invalid binding is refused before any write.
    let mut invalid = binding(namespace);
    invalid.ops = vec!["invalidate".into()];
    assert!(db.put_action_binding(&invalid, "admin", 14).is_err());
}

#[test]
fn sqlite_action_binding_backend_conformance() {
    exercise(&RuntimeDb::memory(), "ops");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_action_binding_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db, "ops");
}
