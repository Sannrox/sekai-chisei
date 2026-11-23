//! Concurrent source refresh and authorized pagination (#824).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::domain::ListFilter;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{self as pb, ListObjectsRequest};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectQueryCursor, ObjectSecurityOperation,
    ObjectSecurityPolicy, ObjectSecurityPredicate, ObjectSecurityRule, PrincipalPolicyContext,
};
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION, SOURCE_GITHUB, SourceBatch,
    SourceBatchStatus, SourceRecord,
};
use sekai_chisei::sekai::source_health::{SourceHealthQuery, project_source_health};
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

const PRODUCER: &str = "connector/github-primary";
const NAMESPACE: &str = "ops";
const VIEWER: &str = "viewer";
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
        // Zero-padded so name order is issue-number order (see `page_visible`).
        display_name: format!("synthetic issue {number:06}"),
        payload_digest: payload.into(),
        properties: BTreeMap::from([
            ("state".into(), "open".into()),
            ("visibility".into(), visibility.into()),
        ]),
        deleted: false,
        observed_at_ms: 10,
        source_sequence: None,
        payload: None,
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
        order_by: "name".into(),
        ..Default::default()
    };
    let context = PrincipalPolicyContext {
        delegated_subject: None,
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

    // Refresh `k` hides issue 2k-1 and shows issue 2k in one batch. The two
    // are adjacent in name order, so the visible total stays `visible` and
    // every other visible issue keeps its slot: a full offset pass must see
    // exactly `visible` distinct issues however refreshes interleave.
    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let refresh_count = Arc::new(AtomicU64::new(0));
    let passes = Arc::new(AtomicU64::new(0));
    let overlapped_passes = Arc::new(AtomicU64::new(0));
    // The first pass reads one page, then waits for the first refresh to
    // commit, so at least one pass overlaps a refresh on every run.
    let (mid_pass_tx, mid_pass_rx) = mpsc::channel::<()>();
    let (refreshed_tx, refreshed_rx) = mpsc::channel::<()>();

    let refresher = {
        let db = Arc::clone(&db);
        let errors = Arc::clone(&errors);
        let refresh_count = Arc::clone(&refresh_count);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            mid_pass_rx.recv().expect("pager reached its first page");
            let mut current = cursor;
            for step in 1..=visible as u64 {
                let next = format!("cursor:{}", step + 1);
                let version = format!("issue-v{}", step + 1);
                let batch = github_batch(
                    &current,
                    &next,
                    &format!("refresh-{step}"),
                    vec![
                        issue_record(step * 2 - 1, &version, PAYLOAD_B, true),
                        issue_record(step * 2, &version, PAYLOAD_B, false),
                    ],
                );
                match retry_locked(|| db.apply_source_batch(&batch, PRODUCER, 200 + step as i64)) {
                    Ok(result) if result.transaction.status == SourceBatchStatus::Committed => {
                        current = next;
                        refresh_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(result) => errors.lock().unwrap().push(format!(
                        "refresh did not commit: {}",
                        result.transaction.reason
                    )),
                    Err(error) => errors.lock().unwrap().push(error),
                }
                if step == 1 {
                    let _ = refreshed_tx.send(());
                }
            }
            stop.store(true, Ordering::SeqCst);
        })
    };

    let pager = {
        let db = Arc::clone(&db);
        let errors = Arc::clone(&errors);
        let refresh_count = Arc::clone(&refresh_count);
        let passes = Arc::clone(&passes);
        let overlapped_passes = Arc::clone(&overlapped_passes);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut mid_pass = Some((mid_pass_tx, refreshed_rx));
            loop {
                let finished = stop.load(Ordering::SeqCst);
                let refreshes_before = refresh_count.load(Ordering::SeqCst);
                let mut offset = 0;
                let mut seen = BTreeSet::new();
                let complete = loop {
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
                            if let Some((tx, rx)) = mid_pass.take() {
                                tx.send(()).expect("refresher waits for the first page");
                                rx.recv().expect("refresher commits its first refresh");
                            }
                            offset += ids.len() as i32;
                            if ids.is_empty() || offset >= total {
                                break true;
                            }
                        }
                        Err(error) => {
                            errors.lock().unwrap().push(error);
                            break false;
                        }
                    }
                };
                if !complete {
                    break;
                }
                if seen.len() != visible {
                    errors.lock().unwrap().push(format!(
                        "a full pass saw {} of {visible} visible issues",
                        seen.len()
                    ));
                }
                passes.fetch_add(1, Ordering::SeqCst);
                if refresh_count.load(Ordering::SeqCst) > refreshes_before {
                    overlapped_passes.fetch_add(1, Ordering::SeqCst);
                }
                // One last pass after the refresher stops reads the final state.
                if finished {
                    break;
                }
            }
        })
    };

    refresher.join().expect("refresh worker panicked");
    pager.join().expect("pagination worker panicked");

    let errors = errors.lock().unwrap().clone();
    assert!(
        errors.is_empty(),
        "concurrent ingestion/query failed: {}",
        errors.join("; ")
    );
    assert_eq!(refresh_count.load(Ordering::SeqCst), visible as u64);
    assert!(
        passes.load(Ordering::SeqCst) >= 2,
        "first pass plus the final pass"
    );
    assert!(
        overlapped_passes.load(Ordering::SeqCst) >= 1,
        "no pagination pass overlapped a refresh"
    );
    // Every refresh committed, so exactly the even issues are visible now.
    let mut final_ids = BTreeSet::new();
    let mut offset = 0;
    loop {
        let (ids, total) = page_visible(&db, offset, 4).unwrap();
        assert_eq!(total, visible as i32);
        if ids.is_empty() {
            break;
        }
        offset += ids.len() as i32;
        final_ids.extend(ids);
    }
    let even: BTreeSet<String> = (1..=visible)
        .map(|k| format!("github:acme/ops#{}", k * 2))
        .collect();
    assert_eq!(final_ids, even);

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
}

fn list_issues(page_token: String, kind: &str) -> Request<ListObjectsRequest> {
    let mut request = Request::new(ListObjectsRequest {
        filter: Some(pb::ListFilter {
            namespace: NAMESPACE.into(),
            kind: kind.into(),
            order_by: "name".into(),
            limit: 2,
            ..Default::default()
        }),
        page_token,
    });
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(VIEWER));
    request
}

/// A page token is bound to its query and to the policy activation it was
/// issued under; presenting it after either changes is refused, as is an
/// expired token.
#[tokio::test]
async fn stale_object_query_cursor_is_refused() {
    let db = Arc::new(RuntimeDb::memory());
    seed_graph(&db, 8);
    let svc = SekaiServiceImpl::new(SekaiStore::from_shared_runtime(Arc::clone(&db)));

    let first = svc
        .list_objects(list_issues(String::new(), "Issue"))
        .await
        .unwrap()
        .into_inner();
    let token = first.next_page_token;
    assert!(!token.is_empty());
    svc.list_objects(list_issues(token.clone(), "Issue"))
        .await
        .expect("the unchanged query resumes from its token");

    let changed = svc
        .list_objects(list_issues(token.clone(), "PullRequest"))
        .await
        .unwrap_err();
    assert_eq!(changed.code(), Code::FailedPrecondition);
    assert!(changed.message().contains("has changed"), "{changed:?}");

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
    let reactivated = svc
        .list_objects(list_issues(token.clone(), "Issue"))
        .await
        .unwrap_err();
    assert_eq!(reactivated.code(), Code::FailedPrecondition);
    assert!(
        reactivated.message().contains("has changed"),
        "{reactivated:?}"
    );

    let key = db.object_query_cursor_key().unwrap();
    let expires_at_ms = ObjectQueryCursor::decode(&token, &key, 0)
        .unwrap()
        .expires_at_ms;
    assert!(ObjectQueryCursor::decode(&token, &key, expires_at_ms - 1).is_ok());
    assert!(ObjectQueryCursor::decode(&token, &key, expires_at_ms).is_err());
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
