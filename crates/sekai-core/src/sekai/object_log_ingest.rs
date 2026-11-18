//! Drains object-log ingest intents (#2289).
//!
//! The transaction that writes an admission's object records an intent with
//! a snapshot of the write and its `seq` among the object's writes; the
//! receipt makes it ready (`crate::db::object_log_ingest`). The admitting
//! request drains its own intent right after the receipt, a replay drains it
//! again, and every replica sweeps the backlog. Admission never waits on the
//! log: a receipt with its intent is the commit, and the backlog gauge shows
//! what the log still lacks.
//!
//! A drain appends the snapshot, merged with the identity's overlay as
//! source ingest would, as Action `sekai.object-log-ingest:<seq>:<gen>`,
//! fenced on the identity's log generation `<gen>`. The log record then names the
//! write it holds, so a drain whose write is not newer than that retires
//! without appending, and an append that raced a newer one is refused by the
//! fence. A record an older replica appended names no write; a drain
//! replaces it only with the committed content, else keeps the intent for a
//! retry. The log never goes back to an older write, whatever the drains'
//! timing, and the snapshot never includes a write that has no receipt.

use std::sync::OnceLock;

use crate::db::object_log_ingest::{ClaimedIntent, IntentScope};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::object_log;

/// How long a claim holds an intent before another replica may retry it.
/// Well past one object-log host round trip, so a slow ingest is not
/// retried while it still runs. Only duplicate work rides on it; the
/// fenced append keeps an overlong drain correct.
const LEASE_MS: i64 = 30_000;
/// Intents one sweep claims.
const SWEEP_BATCH: usize = 64;
/// How long a failed intent waits before a drain retries it, about one
/// sweep interval.
const RETRY_DELAY_MS: i64 = 10_000;
/// Fenced appends one drain tries while other appends keep moving the
/// identity.
const FENCED_ATTEMPTS: usize = 3;

/// This process's claim owner.
fn process_owner() -> &'static str {
    static OWNER: OnceLock<String> = OnceLock::new();
    OWNER.get_or_init(|| format!("object-log-ingest-{}", uuid::Uuid::new_v4()))
}

/// Drains `instance_id`'s intent now, unless another drain holds it.
/// Errors are logged and leave the intent for a later drain.
pub fn drain_instance(db: &RuntimeDb, instance_id: &str) {
    if let Err(error) = drain_one(db, IntentScope::Instance(instance_id), process_owner()) {
        tracing::error!(%instance_id, %error, "object-log ingest intent unavailable");
    }
}

/// One sweep: prunes intents whose admission can no longer receipt, drains
/// up to [`SWEEP_BATCH`] ready ones, then sets the backlog gauge. Safe on
/// every replica at once.
pub fn sweep(db: &RuntimeDb) -> Result<usize, String> {
    sweep_pass(db).map(|pass| pass.drained)
}

/// What one [`sweep_pass`] drained.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct SweepPass {
    pub drained: usize,
    /// Operation ids of the drained admissions, where their instance
    /// records one, in drain order.
    pub operation_ids: Vec<String>,
}

/// [`sweep`], also naming the operations whose intents it drained.
pub fn sweep_pass(db: &RuntimeDb) -> Result<SweepPass, String> {
    db.prune_object_log_ingest_intents()?;
    let mut pass = SweepPass::default();
    for _ in 0..SWEEP_BATCH {
        match drain_one(db, IntentScope::Next, process_owner())? {
            Some((true, instance_id)) => {
                pass.drained += 1;
                // Naming the operation is diagnostic; a failed read must not
                // fail a sweep whose drain already completed.
                if let Some(instance) = db.get_action_instance(&instance_id).ok().flatten()
                    && !instance.operation_id.is_empty()
                {
                    pass.operation_ids.push(instance.operation_id);
                }
            }
            Some((false, _)) => {}
            None => break,
        }
    }
    crate::obs::metrics::set_object_log_ingest_backlog(db.count_object_log_ingest_intents()?);
    Ok(pass)
}

/// Claims one intent `scope` selects and ingests it. `None` when nothing
/// was claimable, else whether the intent completed, with its instance. Each claim covers one
/// ingest, so its lease never has to outlast a batch. A failed ingest
/// hands its intent back: the sweep retries it after [`RETRY_DELAY_MS`],
/// behind intents not yet tried, so refused records cannot starve the
/// backlog.
fn drain_one(
    db: &RuntimeDb,
    scope: IntentScope<'_>,
    owner: &str,
) -> Result<Option<(bool, String)>, String> {
    let now_ms = crate::sekai::action_instance::lease_clock_ms();
    let Some(intent) = db.claim_object_log_ingest_intent(scope, owner, now_ms, LEASE_MS)? else {
        return Ok(None);
    };
    match ingest(db, &intent) {
        Ok(true) => {
            return db
                .complete_object_log_ingest_intent(&intent, owner)
                .map(|completed| Some((completed, intent.instance_id.clone())));
        }
        Ok(false) => {}
        Err(error) => tracing::error!(
            operation_id = %db
                .get_action_instance(&intent.instance_id)
                .ok()
                .flatten()
                .map(|instance| instance.operation_id)
                .unwrap_or_default(),
            instance_id = %intent.instance_id,
            object_id = %intent.object.id,
            object_kind = %intent.object.kind,
            %error,
            "post-receipt object-log ingest failed; admission is durable and \
             its ingest intent stays in the backlog until a drain succeeds"
        ),
    }
    db.release_object_log_ingest_intent(
        &intent.instance_id,
        owner,
        crate::sekai::action_instance::lease_clock_ms().saturating_add(RETRY_DELAY_MS),
    )?;
    Ok(Some((false, intent.instance_id.clone())))
}

/// Appends the intent's snapshot unless the log already holds this write
/// or a newer one. `Ok(false)` when other appends kept moving the identity.
///
/// A record no intent appended (an older replica's, or an overlay
/// rematerialization) has no `seq`, so it
/// cannot show the log holds this write or a newer one. The snapshot
/// replaces it only while the snapshot's content is the committed content:
/// every writer commits before it appends, so a newer write is in the
/// database before its record reaches the log, and the database is read
/// after the fence, so a record appended after that read refuses the
/// append. Otherwise the intent waits for a retry: a later write with an
/// intent retires it once appended, and a compensated one restores this
/// content. It is never retired without evidence.
fn ingest(db: &RuntimeDb, intent: &ClaimedIntent) -> Result<bool, String> {
    for _ in 0..FENCED_ATTEMPTS {
        let Some(fence) = object_log::configured_log_fence(&intent.object)? else {
            return Ok(true);
        };
        if fence
            .ingested_seq
            .is_some_and(|ingested| ingested >= intent.seq)
        {
            return Ok(true);
        }
        // A drain of this write or a newer one completed: an overlay may
        // have rematerialized the record since, under its own Action id.
        if db
            .object_log_ingest_watermark(&intent.object.id)?
            .is_some_and(|drained| drained >= intent.seq)
        {
            return Ok(true);
        }
        // A delete never reaches the log, so a drain must not bring a
        // deleted object back: its write retires unappended, as the
        // receipt-time ingest skipped an absent object.
        let Some(current) = db.get_object(&intent.object.id)? else {
            return Ok(true);
        };
        if fence.holds_unordered_record() && !same_content(&current, &intent.object)? {
            return Ok(false);
        }
        if object_log::apply_fenced_to_configured_log(intent.seq, &intent.object, &fence)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether two states of an object hold the same content. `updated` is
/// left out: compensation restores a write's content under a new `updated`.
fn same_content(
    current: &crate::domain::Object,
    snapshot: &crate::domain::Object,
) -> Result<bool, String> {
    let content = |object: &crate::domain::Object| {
        crate::sekai::action_instance::object_state_digest(Some(&crate::domain::Object {
            updated: 0,
            ..object.clone()
        }))
    };
    Ok(content(current)? == content(snapshot)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;

    fn object(id: &str, name: &str) -> Object {
        Object {
            id: id.into(),
            kind: "customer".into(),
            name: name.into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([("name".into(), name.into())]),
            created: 1,
            updated: 1,
        }
    }

    fn claim(db: &RuntimeDb, scope: IntentScope<'_>, owner: &str, now: i64) -> Option<String> {
        db.claim_object_log_ingest_intent(scope, owner, now, 1_000)
            .unwrap()
            .map(|intent| intent.instance_id)
    }

    #[test]
    fn a_failed_intent_retries_after_intents_never_tried() {
        // Autoreview on #2289: refused records must not starve the backlog.
        let db = RuntimeDb::memory();
        db.record_object_log_ingest_intent("refused", &object("object-refused", "a"), true)
            .unwrap();
        db.record_object_log_ingest_intent("fresh", &object("object-fresh", "b"), true)
            .unwrap();
        assert_eq!(
            claim(&db, IntentScope::Next, "a", 100).as_deref(),
            Some("refused")
        );
        db.release_object_log_ingest_intent("refused", "a", 150)
            .unwrap();
        assert_eq!(
            claim(&db, IntentScope::Next, "a", 200).as_deref(),
            Some("fresh")
        );
        assert_eq!(
            claim(&db, IntentScope::Instance("refused"), "b", 120).as_deref(),
            Some("refused"),
            "a replay retries its own intent at once"
        );
    }

    #[test]
    fn a_live_claim_keeps_other_drainers_off_the_intent() {
        claim_contract(&RuntimeDb::memory(), "sqlite");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_a_live_claim_keeps_other_drainers_off_the_intent() {
        claim_contract(
            &crate::sekai::work_claim_conformance::postgres(),
            &format!("pg{}-{}", std::process::id(), uuid::Uuid::new_v4()),
        );
    }

    /// Two replicas draining one backlog: only a receipted write is
    /// claimable, only one drain holds it, a stale holder cannot complete
    /// a reclaimed intent, and a crashed holder's intent is retried after
    /// its lease. Ids are unique per run, so `Instance` scopes keep a shared
    /// PostgreSQL database's other rows out of it.
    fn claim_contract(db: &RuntimeDb, suffix: &str) {
        let claim = |id: &str, owner, now| claim(db, IntentScope::Instance(id), owner, now);
        let target = object(&format!("object-{suffix}"), "v1");
        let (pending, id) = (format!("pending-{suffix}"), format!("instance-{suffix}"));
        db.record_object_log_ingest_intent(&pending, &target, false)
            .unwrap();
        assert_eq!(claim(&pending, "a", 100), None, "no receipt, no drain");
        db.record_object_log_ingest_intent(&id, &target, true)
            .unwrap();
        assert_eq!(claim(&id, "a", 100), Some(id.clone()));
        assert_eq!(
            claim(&id, "b", 500),
            None,
            "a live claim is not taken twice"
        );
        // `a` crashed: its lease lapses and `b` retries.
        let retried = db
            .claim_object_log_ingest_intent(IntentScope::Instance(&id), "b", 1_100, 1_000)
            .unwrap()
            .unwrap();
        assert!(
            !db.complete_object_log_ingest_intent(&retried, "a").unwrap(),
            "a stale holder cannot complete"
        );
        assert!(db.complete_object_log_ingest_intent(&retried, "b").unwrap());
        assert_eq!(claim(&id, "c", 10_000), None);
        // The earlier write keeps its intent and its place.
        db.mark_object_log_ingest_intent_ready(&pending).unwrap();
        let late = db
            .claim_object_log_ingest_intent(IntentScope::Instance(&pending), "c", 10_000, 1_000)
            .unwrap()
            .unwrap();
        assert!(
            late.seq < retried.seq,
            "a late receipt keeps its write's order"
        );
        // The completion raised the object's watermark; the sweep's
        // promotion and pruning statements run on this backend.
        assert_eq!(
            db.object_log_ingest_watermark(&target.id).unwrap(),
            Some(retried.seq)
        );
        db.prune_object_log_ingest_intents().unwrap();
    }

    #[test]
    fn an_intent_whose_admission_cannot_receipt_is_pruned() {
        // Autoreview on #2289: a released admission leaves no snapshot.
        let db = RuntimeDb::memory();
        db.record_object_log_ingest_intent("released", &object("rec", "v1"), false)
            .unwrap();
        sweep(&db).unwrap();
        db.mark_object_log_ingest_intent_ready("released").unwrap();
        assert_eq!(claim(&db, IntentScope::Instance("released"), "a", 0), None);
    }

    #[test]
    fn a_drain_replaces_an_unordered_record_only_with_the_committed_content() {
        // Autoreview on #2289: an older replica appends without a `seq`.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = RuntimeDb::memory();
        let (pending, newer) = (object("rec", "pending"), object("rec", "newer"));
        db.create_object(&newer).unwrap();
        db.record_object_log_ingest_intent("pending", &pending, true)
            .unwrap();
        db.record_object_log_ingest_intent("current", &newer, true)
            .unwrap();
        let logged = |name: &str| {
            object_log::release_process_object_log_cache();
            let store = mikura::Store::open(&log).unwrap();
            let record = store
                .load("acme", "customer", "rec", &mikura::PropertyAcl::allow_all())
                .unwrap();
            assert_eq!(record.props["name"], name);
        };
        object_log::with_test_log_path(&log, || {
            object_log::ensure_admitted_object_in_configured_log(&newer).unwrap();
            drain_instance(&db, "pending");
            logged("newer");
            assert_eq!(
                db.count_object_log_ingest_intents().unwrap(),
                2,
                "no evidence the log holds it: kept for a retry"
            );
            object_log::ensure_admitted_object_in_configured_log(&pending).unwrap();
            drain_instance(&db, "current");
            logged("newer");
            drain_instance(&db, "pending");
            logged("newer");
            assert_eq!(db.count_object_log_ingest_intents().unwrap(), 0);
        });
    }

    #[test]
    fn a_compensated_later_write_lets_the_receipted_one_land() {
        // Autoreview on #2289: the log holds an older replica's `v0`,
        // receipted `v1` waits, and unreceipted `v2` is compensated back to
        // `v1`'s content under a new `updated`.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = RuntimeDb::memory();
        let (v0, v1) = (object("rec", "v0"), object("rec", "v1"));
        db.create_object(&v1).unwrap();
        db.record_object_log_ingest_intent("v1", &v1, true).unwrap();
        db.update_object(&crate::domain::Object {
            updated: 2,
            ..object("rec", "v2")
        })
        .unwrap();
        object_log::with_test_log_path(&log, || {
            object_log::ensure_admitted_object_in_configured_log(&v0).unwrap();
            drain_instance(&db, "v1");
            assert_eq!(db.count_object_log_ingest_intents().unwrap(), 1);
            db.update_object(&crate::domain::Object {
                updated: 3,
                ..v1.clone()
            })
            .unwrap();
            drain_instance(&db, "v1");
            assert_eq!(db.count_object_log_ingest_intents().unwrap(), 0);
            object_log::release_process_object_log_cache();
            let store = mikura::Store::open(&log).unwrap();
            let record = store
                .load("acme", "customer", "rec", &mikura::PropertyAcl::allow_all())
                .unwrap();
            assert_eq!(record.props["name"], "v1");
        });
    }

    #[test]
    fn a_drain_does_not_bring_a_deleted_object_back() {
        // Autoreview on #2289: the object was deleted before its drain.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = RuntimeDb::memory();
        db.record_object_log_ingest_intent("deleted", &object("gone", "v1"), true)
            .unwrap();
        object_log::with_test_log_path(&log, || {
            drain_instance(&db, "deleted");
            assert_eq!(db.count_object_log_ingest_intents().unwrap(), 0);
            assert!(!object_log::configured_log_shows(&object("gone", "v1")).unwrap());
        });
    }

    #[test]
    fn an_overlay_edit_does_not_strand_a_superseded_write() {
        // Autoreview on #2289: an index edit rematerializes the record under
        // its own Action id after a newer write drained.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = RuntimeDb::memory();
        let (older, newer) = (object("rec", "older"), object("rec", "newer"));
        db.create_object(&newer).unwrap();
        db.record_object_log_ingest_intent("older", &older, false)
            .unwrap();
        db.record_object_log_ingest_intent("newer", &newer, true)
            .unwrap();
        object_log::with_test_log_path(&log, || {
            drain_instance(&db, "newer");
            object_log::release_process_object_log_cache();
            mikura::Store::open(&log)
                .unwrap()
                .apply_overlay(
                    mikura::OverlayPatch {
                        namespace: "acme".into(),
                        kind: "customer".into(),
                        key: "rec".into(),
                        props: std::collections::HashMap::from([("note".into(), "x".into())]),
                        ..Default::default()
                    },
                    "edit-1".into(),
                    None,
                )
                .unwrap();
            db.mark_object_log_ingest_intent_ready("older").unwrap();
            drain_instance(&db, "older");
            assert_eq!(db.count_object_log_ingest_intents().unwrap(), 0);
        });
    }

    #[test]
    fn the_log_never_goes_back_to_an_older_write() {
        // Autoreview on #2289: whatever order drains run in, the log ends
        // on the newest receipted write and never appends an older one.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let db = RuntimeDb::memory();
        // `first` wrote first; its receipt lands after `second` drained.
        db.create_object(&object("rec", "second")).unwrap();
        db.record_object_log_ingest_intent("first", &object("rec", "first"), false)
            .unwrap();
        db.record_object_log_ingest_intent("second", &object("rec", "second"), true)
            .unwrap();
        object_log::with_test_log_path(&log, || {
            drain_instance(&db, "second");
            db.mark_object_log_ingest_intent_ready("first").unwrap();
            drain_instance(&db, "first");
            assert_eq!(db.count_object_log_ingest_intents().unwrap(), 0);
            object_log::release_process_object_log_cache();
            let store = mikura::Store::open(&log).unwrap();
            let record = store
                .load("acme", "customer", "rec", &mikura::PropertyAcl::allow_all())
                .unwrap();
            assert_eq!(record.props["name"], "second");
            assert_eq!(record.r#gen, 1, "the older write appended nothing");
        });
    }
}
