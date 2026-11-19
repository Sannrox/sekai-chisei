//! Namespace audit export behaves the same on SQLite and PostgreSQL (#2638):
//! pages return each of the namespace's decisions once in chain order, a
//! resumed cursor sees decisions written in between, other namespaces never
//! appear, and decisions retention archived are reported, not skipped.

use std::collections::HashMap;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::audit::Decision;
use sekai_chisei::sekai::audit_export::{AuditCursor, AuditExportPage};
use sekai_chisei::sekai::ledger::entry_hash;
use sekai_chisei::sekai::retention::RetentionPolicy;

use crate::postgres_scratch::ScratchDatabase;

const OLD: i64 = 1_000;

fn decide(db: &RuntimeDb, id: &str, namespace: &str, timestamp: i64) {
    db.record_decision(&Decision {
        id: id.into(),
        timestamp,
        actor: "alice".into(),
        action: "test".into(),
        reason: String::new(),
        evidence: HashMap::from([("namespace".into(), namespace.into())]),
        target_id: String::new(),
        outcome: "allow".into(),
    })
    .unwrap();
}

fn ids(page: &AuditExportPage) -> Vec<&str> {
    page.records
        .iter()
        .map(|record| record.decision.id.as_str())
        .collect()
}

fn exercise(db: &RuntimeDb) {
    let now = chrono::Utc::now().timestamp_millis();
    decide(db, "old-acme", "acme", OLD);
    decide(db, "old-other", "other", OLD);
    decide(db, "acme-1", "acme", now);
    decide(db, "other-1", "other", now);
    decide(db, "acme-2", "acme", now);

    let first = db.export_namespace_audit("acme", None, 2).unwrap();
    assert_eq!(ids(&first), ["old-acme", "acme-1"]);
    assert!(!first.caught_up);
    assert_eq!(first.archived_through_seq, 0);
    for record in &first.records {
        assert_eq!(
            entry_hash(
                record.seq,
                &record.prev_hash,
                &record.decision,
                &record.evidence_json
            ),
            record.entry_hash,
            "a reader recomputes each record's hash from what the page carries"
        );
    }

    // Written while the caller is paused: the resumed page sees it, once.
    decide(db, "acme-3", "acme", now);
    let cursor = AuditCursor::parse(&first.next_cursor.encode())
        .unwrap()
        .unwrap();
    let second = db
        .export_namespace_audit("acme", Some(&cursor), 10)
        .unwrap();
    assert_eq!(ids(&second), ["acme-2", "acme-3"]);
    assert!(second.caught_up);
    assert_eq!(second.verified_from, first.next_cursor);

    let other = db.export_namespace_audit("other", None, 10).unwrap();
    assert_eq!(ids(&other), ["old-other", "other-1"]);

    // Retention archives the two old decisions; a cursor from before that,
    // and a fresh export, both report the archived range.
    db.set_retention_policy(&RetentionPolicy {
        dataset: "audit".into(),
        namespace: String::new(),
        data_class: String::new(),
        retention_days: 1,
        updated: now,
    })
    .unwrap();
    db.archive_retained_records(now, false).unwrap();
    let genesis = AuditCursor::genesis();
    for cursor in [None, Some(&genesis)] {
        let page = db.export_namespace_audit("acme", cursor, 10).unwrap();
        assert_eq!(page.archived_through_seq, 2);
        assert_eq!(ids(&page), ["acme-1", "acme-2", "acme-3"]);
    }
    let resumed = db
        .export_namespace_audit("acme", Some(&second.next_cursor), 10)
        .unwrap();
    assert_eq!(resumed.archived_through_seq, 0);
    assert!(resumed.records.is_empty() && resumed.caught_up);
}

#[test]
fn sqlite_audit_export_conformance() {
    exercise(&RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_audit_export_conformance() {
    let scratch = ScratchDatabase::create();
    exercise(&RuntimeDb::Postgres(Arc::new(scratch.connect(8))));
}
