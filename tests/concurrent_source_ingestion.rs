//! Concurrent source refresh and authorized pagination (#824).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Instant;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::domain::ListFilter;
use sekai_chisei::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectQueryCursor, ObjectSecurityOperation,
    ObjectSecurityPolicy, ObjectSecurityPredicate, ObjectSecurityRule, PrincipalPolicyContext,
    object_query_digest, object_security_activation_digest,
};
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION, SOURCE_GITHUB, SourceBatch,
    SourceBatchStatus, SourceRecord,
};
use sekai_chisei::sekai::source_health::{SourceHealthQuery, project_source_health};

const PRODUCER: &str = "connector/github-primary";
const NAMESPACE: &str = "ops";
const SOURCE_INSTANCE: &str = "acme/ops";
const PAYLOAD_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PAYLOAD_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn payload_digest(index: usize) -> String {
    format!("sha256:{:064x}", index + 1)
}

fn issue_record(number: u64, version: &str, payload: &str, hidden: bool) -> SourceRecord {
    let visibility = if hidden { "hidden" } else { "visible" };
    SourceRecord {
        source: SOURCE_GITHUB.into(),
        source_instance: SOURCE_INSTANCE.into(),
        external_id: number.to_string(),
        source_version: version.into(),
        type_name: "Issue".into(),
        display_name: format!("synthetic issue {number}"),
        payload_digest: payload.into(),
        properties: BTreeMap::from([
            ("state".into(), "open".into()),
            ("visibility".into(), visibility.into()),
        ]),
        deleted: false,
        observed_at_ms: 10,
        source_sequence: None,
    }
}

fn github_batch(current: &str, next: &str, key: &str, records: Vec<SourceRecord>) -> SourceBatch {
    let mut batch = SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: NAMESPACE.into(),
        producer_identity: PRODUCER.into(),
        source: SOURCE_GITHUB.into(),
        source_instance: SOURCE_INSTANCE.into(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        current_cursor: current.into(),
        proposed_next_cursor: next.into(),
        idempotency_key: key.into(),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records,
        delivery: None,
    };
    batch.batch_digest = batch.canonical_digest().unwrap();
    batch
}

fn visibility_policy() -> ObjectSecurityPolicy {
    ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: NAMESPACE.into(),
        kind: "Issue".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::PropertyEquals {
                property: "visibility".into(),
                value: "visible".into(),
            }],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: None,
    }
}

fn seed_graph(db: &RuntimeDb, size: usize) -> String {
    assert!(
        size >= 2 && size.is_multiple_of(2),
        "graph size must be even"
    );
    let records = (1..=size as u64)
        .map(|number| {
            let hidden = number % 2 == 0;
            issue_record(number, "issue-v1", &payload_digest(number as usize), hidden)
        })
        .collect::<Vec<_>>();
    let first = github_batch("", "cursor:1", "seed", records);
    let admitted = db.apply_source_batch(&first, PRODUCER, 100).unwrap();
    assert_eq!(admitted.transaction.status, SourceBatchStatus::Committed);
    let revision = db
        .put_object_security_policy(&visibility_policy(), "local", "put-visibility", 110)
        .unwrap();
    db.activate_object_security_policies(
        NAMESPACE,
        &BTreeMap::from([("Issue".into(), revision.revision_digest)]),
        "local",
        "activate-visibility",
        120,
    )
    .unwrap();
    "cursor:1".into()
}

fn resident_memory_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages = status.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(pages.saturating_mul(4096))
}

fn retry_locked<T>(mut operation: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    const MAX_ATTEMPTS: usize = 20;
    for attempt in 1..=MAX_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.contains("database is locked") && attempt < MAX_ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Err("database is locked: retry bound exhausted".into())
}

fn page_visible(db: &RuntimeDb, offset: i32, limit: i32) -> Result<(Vec<String>, i32), String> {
    let filter = ListFilter {
        namespace: Some(NAMESPACE.into()),
        kind: Some("Issue".into()),
        limit,
        offset,
        ..Default::default()
    };
    let context = PrincipalPolicyContext {
        subjects: vec!["viewer".into()],
        scopes: vec![],
    };
    let (objects, total) =
        db.list_objects_with_total_for_policy_context(&filter, &["viewer"], &[], &context)?;
    let ids = objects
        .into_iter()
        .map(|object| {
            if object.properties.get("visibility").map(String::as_str) != Some("visible") {
                return Err(format!("unauthorized disclosure of {}", object.external_id));
            }
            Ok(object.external_id)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((ids, total))
}

fn exercise_size(size: usize) {
    let db = Arc::new(RuntimeDb::memory());
    let cursor = seed_graph(&db, size);
    let visible = size / 2;
    let (first_page, total) = retry_locked(|| page_visible(&db, 0, 4)).unwrap();
    assert_eq!(total, visible as i32);
    assert!(!first_page.is_empty());
    assert!(
        first_page
            .iter()
            .all(|id| id.starts_with("github:acme/ops#"))
    );

    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let refresh_count = Arc::new(AtomicU64::new(0));
    let listed_hidden = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(2));
    let started = Instant::now();

    let refresher = {
        let db = Arc::clone(&db);
        let errors = Arc::clone(&errors);
        let refresh_count = Arc::clone(&refresh_count);
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            barrier.wait();
            let mut current = cursor;
            for step in 1..=visible {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let number = (step as u64 * 2) - 1;
                let next = format!("cursor:{}", step + 1);
                let batch = github_batch(
                    &current,
                    &next,
                    &format!("refresh-{step}"),
                    vec![issue_record(
                        number,
                        &format!("issue-v{}", step + 1),
                        PAYLOAD_B,
                        false,
                    )],
                );
                match retry_locked(|| db.apply_source_batch(&batch, PRODUCER, 200 + step as i64)) {
                    Ok(result) if result.transaction.status == SourceBatchStatus::Committed => {
                        current = next;
                        refresh_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(result) => errors.lock().unwrap().push(format!(
                        "refresh did not commit: {}",
                        result.transaction.reason
                    )),
                    Err(error) => errors.lock().unwrap().push(error),
                }
            }
            stop.store(true, Ordering::Relaxed);
        })
    };

    let pager = {
        let db = Arc::clone(&db);
        let errors = Arc::clone(&errors);
        let listed_hidden = Arc::clone(&listed_hidden);
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                let mut offset = 0;
                let mut seen = BTreeSet::new();
                loop {
                    match retry_locked(|| page_visible(&db, offset, 4)) {
                        Ok((ids, total)) => {
                            if total != visible as i32 {
                                errors.lock().unwrap().push(format!(
                                    "visible total drifted from {visible} to {total}"
                                ));
                            }
                            for id in &ids {
                                if !seen.insert(id.clone()) {
                                    errors
                                        .lock()
                                        .unwrap()
                                        .push(format!("silent cursor mismatch duplicated {id}"));
                                }
                            }
                            if ids.is_empty() {
                                break;
                            }
                            offset += ids.len() as i32;
                            if offset >= total {
                                break;
                            }
                        }
                        Err(error) if error.starts_with("unauthorized disclosure") => {
                            listed_hidden.fetch_add(1, Ordering::Relaxed);
                            errors.lock().unwrap().push(error);
                            break;
                        }
                        Err(error) => {
                            errors.lock().unwrap().push(error);
                            break;
                        }
                    }
                }
            }
        })
    };

    refresher.join().expect("refresh worker panicked");
    pager.join().expect("pagination worker panicked");
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs_f64() > 0.0,
        "incomplete run produced no elapsed time"
    );

    let errors = errors.lock().unwrap().clone();
    assert!(
        errors.is_empty(),
        "concurrent ingestion/query failed: {}",
        errors.join("; ")
    );
    assert_eq!(listed_hidden.load(Ordering::Relaxed), 0);
    assert!(refresh_count.load(Ordering::Relaxed) > 0);
    let memory = resident_memory_bytes();
    assert!(
        memory.is_none() || memory.unwrap() > 0,
        "memory observation must be unavailable or a positive RSS"
    );

    let state = db
        .get_source_sync_state(NAMESPACE, SOURCE_INSTANCE, GITHUB_OBJECT_SYNC_TYPE_DIGEST)
        .unwrap()
        .unwrap();
    let health = project_source_health(
        &state,
        &SourceHealthQuery {
            namespace: NAMESPACE.into(),
            source_instance: SOURCE_INSTANCE.into(),
            type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
            delayed_after_ms: 15 * 60 * 1000,
            contract_version: None,
        },
        10_000,
    );
    assert!(health.lag.is_some() || health.checkpoint_age_ms.is_some());

    let stale = github_batch(
        "cursor:foreign",
        "cursor:stale",
        "stale",
        vec![issue_record(1, "issue-stale", PAYLOAD_A, false)],
    );
    assert!(
        db.apply_source_batch(&stale, PRODUCER, 9_000)
            .unwrap_err()
            .starts_with("stale_cursor:")
    );

    let filter = ListFilter {
        namespace: Some(NAMESPACE.into()),
        kind: Some("Issue".into()),
        limit: 4,
        offset: 0,
        ..Default::default()
    };
    let query_digest = object_query_digest(&filter).unwrap();
    let activation = db
        .get_object_security_activation(NAMESPACE)
        .unwrap()
        .unwrap();
    let activation_digest = object_security_activation_digest(&activation).unwrap();
    let key = db.object_query_cursor_key().unwrap();
    let token = ObjectQueryCursor::issue(
        4,
        "a".repeat(64),
        NAMESPACE.into(),
        activation_digest.clone(),
        query_digest.clone(),
        1_000,
    )
    .unwrap()
    .encode(&key)
    .unwrap();
    let decoded = ObjectQueryCursor::decode(&token, &key, 1_001).unwrap();
    assert_eq!(decoded.query_digest, query_digest);

    let mut changed = filter.clone();
    changed.kind = Some("PullRequest".into());
    let changed_digest = object_query_digest(&changed).unwrap();
    assert_ne!(changed_digest, query_digest);

    let replacement = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: NAMESPACE.into(),
        kind: "Issue".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: None,
    };
    let next_revision = db
        .put_object_security_policy(&replacement, "local", "put-allow-all", 9_100)
        .unwrap();
    db.activate_object_security_policies(
        NAMESPACE,
        &BTreeMap::from([("Issue".into(), next_revision.revision_digest)]),
        "local",
        "activate-allow-all",
        9_200,
    )
    .unwrap();
    let next_activation = db
        .get_object_security_activation(NAMESPACE)
        .unwrap()
        .unwrap();
    assert_ne!(
        object_security_activation_digest(&next_activation).unwrap(),
        activation_digest
    );
}

#[test]
fn small_medium_and_large_graphs_keep_refresh_and_pagination_atomic() {
    for size in [8, 32, 96] {
        exercise_size(size);
    }
}

#[test]
fn incomplete_refresh_is_not_a_pass() {
    let db = RuntimeDb::memory();
    seed_graph(&db, 4);
    let batch = github_batch(
        "cursor:1",
        "cursor:2",
        "partial",
        vec![
            issue_record(1, "issue-v2", PAYLOAD_B, false),
            issue_record(1, "issue-v2b", PAYLOAD_A, false),
        ],
    );
    let err = db.apply_source_batch(&batch, PRODUCER, 300).unwrap_err();
    assert!(err.starts_with("ambiguous_record_identity:"), "{err}");
    assert_eq!(
        db.get_source_sync_state(NAMESPACE, SOURCE_INSTANCE, GITHUB_OBJECT_SYNC_TYPE_DIGEST)
            .unwrap()
            .unwrap()
            .checkpoint
            .unwrap()
            .cursor,
        "cursor:1"
    );
}
