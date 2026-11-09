//! Source sync as the `source_sync` work kind (ADR 0148, ADR 0149).
//!
//! A Source with `every_ms > 0` is a member of the transform schedule
//! graph. Each tick moves its due bucket to `now / every_ms` in one
//! idempotent statement, so replicas ticking together raise it once. A due
//! bucket the Source has not finished is claimable work for a connector
//! runtime whose labels satisfy the Source's placement. The claim record and
//! the sync outcome live in the Source row, and the claim engine
//! ([`crate::sekai::work_claim`]) decides who holds it.
//!
//! A claim covers the newest due bucket, so a runtime that fell behind
//! syncs once, not once per missed bucket. Acknowledging completes or fails
//! the bucket. A completion closes the claimed bucket, so a bucket that came
//! due during a long sync is synced once more. A failure closes every bucket
//! due so far and waits for the next instead of retrying, so a credential
//! the runtime cannot resolve reports `unavailable` once per interval, never
//! in a loop. The third lapsed lease fails the same way, as
//! `lease_expired`. Disabling the Source, or changing its interval, raises
//! the claim generation, so no earlier fence can heartbeat or acknowledge.

use std::collections::BTreeMap;

use sekai_types::governed_transform::{
    MAX_TRANSFORM_LEASE_EXPIRIES, normalize_transform_claim_ttl_ms, placement_satisfied,
};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::source::{MAX_LIST_SOURCES, Source, SourceStatus};
use crate::sekai::work_claim::{ClaimError, ClaimRecord, Fence, Hold};

/// A bucket fails on the lapse that reaches this count.
pub const MAX_SOURCE_SYNC_LEASE_EXPIRIES: i64 = MAX_TRANSFORM_LEASE_EXPIRIES;

/// Where a Source's sync stands, as stored in its row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    /// The newest bucket the schedule made due.
    pub due_bucket: i64,
    /// The bucket the current or last claim covers.
    pub claimed_bucket: i64,
    /// The newest bucket that completed or failed.
    pub done_bucket: i64,
    pub claim: ClaimRecord,
    pub last_success_at_ms: i64,
    pub last_failure_at_ms: i64,
    /// The wire name of the last [`SyncFailure`]; empty for none. Kept as
    /// text so a plane reads a class a newer runtime reported.
    pub last_failure: String,
    /// The runtime that finished the last bucket.
    pub last_runtime: String,
}

/// Why a sync bucket failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncFailure {
    /// The runtime could not resolve the credential handle.
    Unavailable,
    Unreachable,
    AuthFailed,
    PermissionMissing,
    Invalid,
    Unsupported,
    /// The lease lapsed too often.
    LeaseExpired,
}

impl SyncFailure {
    pub const ALL: [SyncFailure; 7] = [
        Self::Unavailable,
        Self::Unreachable,
        Self::AuthFailed,
        Self::PermissionMissing,
        Self::Invalid,
        Self::Unsupported,
        Self::LeaseExpired,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Unreachable => "unreachable",
            Self::AuthFailed => "auth_failed",
            Self::PermissionMissing => "permission_missing",
            Self::Invalid => "invalid",
            Self::Unsupported => "unsupported",
            Self::LeaseExpired => "lease_expired",
        }
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|failure| failure.wire_name() == name)
    }
}

/// How a runtime finished a claimed bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncOutcome {
    Completed,
    Failed(SyncFailure),
}

/// Why a sync call was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncError {
    NotFound,
    /// The runtime's labels do not satisfy the Source's placement.
    Placement,
    /// The owner is empty.
    Owner,
    /// The claim engine refused the transition.
    Claim(ClaimError),
    Store(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("source not found"),
            Self::Placement => formatter.write_str("runtime labels do not satisfy placement"),
            Self::Owner => formatter.write_str("claim owner is required"),
            Self::Claim(error) => error.fmt(formatter),
            Self::Store(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<String> for SyncError {
    fn from(error: String) -> Self {
        Self::Store(error)
    }
}

impl Source {
    /// What the Source's state means for its sync claim.
    pub fn sync_hold(&self) -> Hold {
        if self.status != SourceStatus::Active {
            Hold::Closed
        } else if self.sync.claim.expires_at_ms > 0 {
            Hold::Held
        } else if self.sync.due_bucket > self.sync.done_bucket {
            Hold::Open
        } else {
            Hold::Closed
        }
    }
}

impl SyncState {
    /// Ends the claimed bucket; a failure also ends every bucket due by
    /// now, so the next attempt waits for the next interval. The owner,
    /// generation and token stay, so a retried acknowledge under the same
    /// fence can be matched.
    fn finish(&mut self, outcome: SyncOutcome, now_ms: i64) {
        self.done_bucket = match outcome {
            SyncOutcome::Completed => self.claimed_bucket,
            SyncOutcome::Failed(_) => self.claimed_bucket.max(self.due_bucket),
        };
        self.claim.expires_at_ms = 0;
        self.claim.lease_expiries = 0;
        self.last_runtime = self.claim.owner.clone();
        match outcome {
            SyncOutcome::Completed => self.last_success_at_ms = now_ms,
            SyncOutcome::Failed(failure) => {
                self.last_failure_at_ms = now_ms;
                self.last_failure = failure.wire_name().into();
            }
        }
    }
}

/// Makes every scheduled, active Source due for the current bucket.
/// Idempotent, so every replica may tick.
pub fn tick(db: &RuntimeDb, now_ms: i64) -> Result<u64, String> {
    db.tick_source_syncs("", now_ms)
}

/// At most `limit` Sources in `namespace` a runtime with `labels` may
/// claim now, by id. Placement filters while walking every due Source, so
/// due work placed elsewhere never hides work this runtime may take.
pub fn list_claimable(
    db: &RuntimeDb,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    now_ms: i64,
    limit: usize,
) -> Result<Vec<Source>, String> {
    walk_claimable(db, namespace, labels, now_ms, limit, MAX_LIST_SOURCES)
}

fn walk_claimable(
    db: &RuntimeDb,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    now_ms: i64,
    limit: usize,
    page: usize,
) -> Result<Vec<Source>, String> {
    let mut claimable = Vec::new();
    let mut after = String::new();
    while claimable.len() < limit {
        let due = db.list_due_source_syncs(namespace, &after, now_ms, page)?;
        let last_page = due.len() < page;
        if let Some(last) = due.last() {
            after.clone_from(&last.source_id);
        }
        claimable.extend(due.into_iter().filter(|source| {
            source.sync.claim.is_takeable(
                source.sync_hold(),
                MAX_SOURCE_SYNC_LEASE_EXPIRIES,
                now_ms,
            ) && placement_satisfied(&source.spec.placement, labels)
        }));
        if last_page {
            break;
        }
    }
    claimable.truncate(limit);
    Ok(claimable)
}

/// Claims the Source's due bucket for `owner`. The claim returns the Source
/// with its spec, so the runtime syncs the configuration it was granted
/// under.
pub fn claim(
    db: &RuntimeDb,
    namespace: &str,
    source_id: &str,
    owner: &str,
    labels: &BTreeMap<String, String>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<Source, SyncError> {
    if owner.trim().is_empty() {
        return Err(SyncError::Owner);
    }
    let source = db.edit_source_sync(namespace, source_id, |source| {
        if !placement_satisfied(&source.spec.placement, labels) {
            return Err(SyncError::Placement);
        }
        let hold = source.sync_hold();
        let sync = &mut source.sync;
        match sync
            .claim
            .count_lapse(hold, MAX_SOURCE_SYNC_LEASE_EXPIRIES, now_ms)
        {
            Ok(_) => {}
            Err(ClaimError::LeaseLimit) => {
                // Fails the bucket and ends the lapsed claim, so its fence
                // cannot replay an acknowledge.
                sync.finish(SyncOutcome::Failed(SyncFailure::LeaseExpired), now_ms);
                sync.claim.fencing_token.clear();
                return Ok(());
            }
            Err(error) => return Err(SyncError::Claim(error)),
        }
        sync.claimed_bucket = sync.due_bucket;
        sync.claim.grant(
            owner,
            normalize_transform_claim_ttl_ms(ttl_ms),
            now_ms,
            |_| uuid::Uuid::new_v4().to_string(),
        );
        Ok(())
    })?;
    if source.sync.claim.expires_at_ms == 0 {
        return Err(SyncError::Claim(ClaimError::LeaseLimit));
    }
    Ok(source)
}

/// Extends the live claim `fence`.
pub fn heartbeat(
    db: &RuntimeDb,
    namespace: &str,
    source_id: &str,
    fence: Fence<'_>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<Source, SyncError> {
    db.edit_source_sync(namespace, source_id, |source| {
        let hold = source.sync_hold();
        source
            .sync
            .claim
            .heartbeat(
                hold,
                fence,
                normalize_transform_claim_ttl_ms(ttl_ms),
                now_ms,
            )
            .map_err(SyncError::Claim)
    })
}

/// Finishes the claimed bucket under the live `fence`. A retry under the
/// fence that finished it succeeds without writing a second outcome.
pub fn acknowledge(
    db: &RuntimeDb,
    namespace: &str,
    source_id: &str,
    fence: Fence<'_>,
    outcome: SyncOutcome,
    now_ms: i64,
) -> Result<Source, SyncError> {
    db.edit_source_sync(namespace, source_id, |source| {
        let hold = source.sync_hold();
        let sync = &mut source.sync;
        if hold != Hold::Held
            && sync.claim.matches(fence)
            && sync.done_bucket >= sync.claimed_bucket
        {
            return Ok(());
        }
        sync.claim
            .release(hold, fence, now_ms)
            .map_err(SyncError::Claim)?;
        sync.finish(outcome, now_ms);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::source::{self, tests::github};
    use std::sync::Arc;

    /// The interval [`github`] puts.
    const EVERY: i64 = 300_000;
    const TTL: i64 = 1_000;

    fn labels(zone: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("zone".into(), zone.into())])
    }

    fn fence(source: &Source) -> Fence<'_> {
        Fence {
            owner: &source.sync.claim.owner,
            generation: source.sync.claim.generation,
            token: &source.sync.claim.fencing_token,
        }
    }

    fn claimable(db: &RuntimeDb, ns: &str, now_ms: i64) -> Vec<String> {
        list_claimable(db, ns, &labels("eu"), now_ms, MAX_LIST_SOURCES)
            .unwrap()
            .into_iter()
            .map(|source| source.source_id)
            .collect()
    }

    fn take(db: &RuntimeDb, ns: &str, owner: &str, now_ms: i64) -> Result<Source, SyncError> {
        claim(db, ns, "repo", owner, &labels("eu"), TTL, now_ms)
    }

    /// The source_sync kind on either backend: schedule, placement, crash
    /// and takeover, no retry loop on failure, and disable fencing.
    fn contract(db: &RuntimeDb, ns: &str) {
        source::put(db, &github(ns, "repo", "acme/repo")).unwrap();
        // An unscheduled Source is never due, and the tick does not divide
        // by its zero interval.
        let mut idle = github(ns, "idle", "acme/idle");
        idle.spec.every_ms = 0;
        source::put(db, &idle).unwrap();
        assert!(
            claimable(db, ns, 0).is_empty(),
            "nothing is due before a tick"
        );

        // Two replicas ticking the same bucket make it due once.
        let now = 10 * EVERY + 5;
        db.tick_source_syncs(ns, now).unwrap();
        db.tick_source_syncs(ns, now).unwrap();
        let due = db.get_source(ns, "repo").unwrap().unwrap();
        assert_eq!(due.sync.due_bucket, 10);
        assert_eq!(claimable(db, ns, now), ["repo"]);

        // Placement: a runtime without the labels neither lists nor claims.
        assert!(
            list_claimable(db, ns, &labels("us"), now, MAX_LIST_SOURCES)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            claim(db, ns, "repo", "rt-us", &labels("us"), TTL, now),
            Err(SyncError::Placement)
        );

        let crashed = take(db, ns, "rt-1", now).unwrap();
        assert_eq!(crashed.sync.claimed_bucket, 10);
        assert_eq!(
            take(db, ns, "rt-2", now + 1),
            Err(SyncError::Claim(ClaimError::Held))
        );

        // The first runtime crashes mid-claim. After its lease lapses a
        // second takes over under a higher generation, and the crashed
        // runtime's fence is refused.
        let current = take(db, ns, "rt-2", now + TTL + 1).unwrap();
        assert!(current.sync.claim.generation > crashed.sync.claim.generation);
        assert_eq!(
            heartbeat(db, ns, "repo", fence(&crashed), TTL, now + TTL + 2),
            Err(SyncError::Claim(ClaimError::FenceLost))
        );
        assert_eq!(
            acknowledge(
                db,
                ns,
                "repo",
                fence(&crashed),
                SyncOutcome::Completed,
                now + TTL + 2
            ),
            Err(SyncError::Claim(ClaimError::FenceLost))
        );

        // The current claim completes; its retry changes nothing.
        let done = acknowledge(
            db,
            ns,
            "repo",
            fence(&current),
            SyncOutcome::Completed,
            now + TTL + 3,
        )
        .unwrap();
        assert_eq!(
            (
                done.sync.done_bucket,
                done.sync.last_success_at_ms,
                done.sync.last_runtime.as_str(),
                done.sync.claim.lease_expiries,
            ),
            (10, now + TTL + 3, "rt-2", 0)
        );
        assert_eq!(
            acknowledge(
                db,
                ns,
                "repo",
                fence(&current),
                SyncOutcome::Completed,
                now + TTL + 9
            ),
            Ok(done)
        );
        assert!(claimable(db, ns, now + TTL + 9).is_empty());

        // An unresolved credential fails the bucket once. The next attempt
        // waits for the next bucket, even when one came due mid-claim: no
        // retry loop.
        let next = 11 * EVERY;
        db.tick_source_syncs(ns, next).unwrap();
        let held = take(db, ns, "rt-1", next).unwrap();
        let crossed = 12 * EVERY;
        // A heartbeat carries the claim past the next bucket.
        heartbeat(db, ns, "repo", fence(&held), EVERY, next + TTL / 2).unwrap();
        db.tick_source_syncs(ns, crossed).unwrap();
        let failed = acknowledge(
            db,
            ns,
            "repo",
            fence(&held),
            SyncOutcome::Failed(SyncFailure::Unavailable),
            crossed + 1,
        )
        .unwrap();
        assert_eq!(
            (
                failed.sync.last_failure.as_str(),
                failed.sync.last_failure_at_ms,
                failed.sync.done_bucket,
            ),
            ("unavailable", crossed + 1, 12)
        );
        db.tick_source_syncs(ns, crossed + 2).unwrap();
        assert!(claimable(db, ns, crossed + 2).is_empty());
        assert_eq!(
            take(db, ns, "rt-1", crossed + 2),
            Err(SyncError::Claim(ClaimError::Closed))
        );

        // A plane that fell behind syncs the newest bucket once.
        let late = 15 * EVERY;
        db.tick_source_syncs(ns, late).unwrap();
        let held = take(db, ns, "rt-1", late).unwrap();
        assert_eq!(held.sync.claimed_bucket, 15);

        // Disabling raises the generation, so the live fence is refused,
        // and the schedule no longer makes the Source due.
        let disabled = source::disable(db, ns, "repo", late + 1).unwrap();
        assert!(disabled.sync.claim.generation > held.sync.claim.generation);
        assert_eq!(
            heartbeat(db, ns, "repo", fence(&held), TTL, late + 2),
            Err(SyncError::Claim(ClaimError::FenceLost))
        );
        assert_eq!(
            acknowledge(
                db,
                ns,
                "repo",
                fence(&held),
                SyncOutcome::Completed,
                late + 2
            ),
            Err(SyncError::Claim(ClaimError::FenceLost))
        );
        db.tick_source_syncs(ns, 16 * EVERY).unwrap();
        assert!(claimable(db, ns, 16 * EVERY).is_empty());
        assert_eq!(
            take(db, ns, "rt-1", 16 * EVERY),
            Err(SyncError::Claim(ClaimError::Closed))
        );

        // Re-enabling resumes the unfinished bucket.
        let mut enable = github(ns, "repo", "acme/repo");
        enable.expected_revision = disabled.revision;
        let enabled = source::put(db, &enable).unwrap();
        assert_eq!(enabled.sync.due_bucket, 15);
        assert_eq!(claimable(db, ns, 16 * EVERY), ["repo"]);

        // A changed interval restarts the schedule in the new unit, and
        // ends the live claim under a raised generation.
        let live = take(db, ns, "rt-1", 16 * EVERY).unwrap();
        let mut slower = github(ns, "repo", "acme/repo");
        slower.expected_revision = live.revision;
        slower.spec.every_ms = 2 * EVERY;
        let slower = source::put(db, &slower).unwrap();
        assert_eq!((slower.sync.due_bucket, slower.sync.done_bucket), (0, 0));
        assert!(slower.sync.claim.generation > live.sync.claim.generation);
        assert_eq!(
            heartbeat(db, ns, "repo", fence(&live), TTL, 16 * EVERY + 1),
            Err(SyncError::Claim(ClaimError::FenceLost))
        );
        db.tick_source_syncs(ns, 16 * EVERY).unwrap();
        assert_eq!(
            db.get_source(ns, "repo").unwrap().unwrap().sync.due_bucket,
            8
        );
    }

    #[test]
    fn sqlite_source_sync_contract() {
        contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_source_sync_contract() {
        let ns = format!(
            "source-sync-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        contract(&crate::sekai::work_claim_conformance::postgres(), &ns);
    }

    #[test]
    fn due_work_placed_elsewhere_does_not_hide_claimable_work() {
        let db = RuntimeDb::memory();
        for (id, zone) in [("a", "us"), ("b", "us"), ("c", "eu"), ("d", "eu")] {
            let mut put = github("acme", id, &format!("acme/{id}"));
            put.spec.placement = labels(zone);
            source::put(&db, &put).unwrap();
        }
        let now = 10 * EVERY;
        db.tick_source_syncs("acme", now).unwrap();
        // One due row per page: the walk passes both us rows to find eu.
        let found = walk_claimable(&db, "acme", &labels("eu"), now, 1, 1).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source_id, "c");
        let all = walk_claimable(&db, "acme", &labels("eu"), now, 10, 1).unwrap();
        assert_eq!(
            all.iter()
                .map(|source| source.source_id.as_str())
                .collect::<Vec<_>>(),
            ["c", "d"]
        );
    }

    #[test]
    fn an_older_sources_table_gains_the_sync_columns() {
        let RuntimeDb::Sqlite(sqlite) = RuntimeDb::memory() else {
            unreachable!()
        };
        // The table as the plane before the sync columns created it.
        sqlite
            .conn()
            .execute_batch(
                "DROP TABLE sekai_sources;
                 CREATE TABLE sekai_sources (
                     namespace TEXT NOT NULL, source_id TEXT NOT NULL,
                     source TEXT NOT NULL, source_instance TEXT NOT NULL,
                     status TEXT NOT NULL, revision INTEGER NOT NULL,
                     created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
                     record_json TEXT NOT NULL,
                     PRIMARY KEY (namespace, source_id),
                     UNIQUE (namespace, source, source_instance));",
            )
            .unwrap();
        let spec = source::validate(&github("acme", "repo", "acme/repo")).unwrap();
        sqlite
            .conn()
            .execute(
                "INSERT INTO sekai_sources VALUES
                 ('acme', 'repo', 'github', 'acme/repo', 'active', 1, 1, 1, ?1)",
                [serde_json::to_string(&spec).unwrap()],
            )
            .unwrap();
        sqlite.migrate_sources().unwrap();
        sqlite.migrate_sources().unwrap();
        let db = RuntimeDb::Sqlite(Arc::clone(&sqlite));
        let upgraded = db.get_source("acme", "repo").unwrap().unwrap();
        assert_eq!(upgraded.sync, SyncState::default());
        // The tick copies the interval from the spec, so the schedule picks
        // up a row an older plane wrote.
        db.tick_source_syncs("acme", 10 * EVERY).unwrap();
        assert_eq!(claimable(&db, "acme", 10 * EVERY), ["repo"]);

        // An older plane that unschedules the Source rewrites only the
        // spec; the next tick follows it.
        let mut unscheduled = spec.clone();
        unscheduled.every_ms = 0;
        sqlite
            .conn()
            .execute(
                "UPDATE sekai_sources SET record_json = ?1",
                [serde_json::to_string(&unscheduled).unwrap()],
            )
            .unwrap();
        db.tick_source_syncs("acme", 11 * EVERY).unwrap();
        assert!(claimable(&db, "acme", 11 * EVERY).is_empty());
    }

    #[test]
    fn failure_wire_names_round_trip() {
        for failure in SyncFailure::ALL {
            assert_eq!(
                SyncFailure::from_wire_name(failure.wire_name()),
                Some(failure)
            );
        }
        assert_eq!(SyncFailure::from_wire_name("completed"), None);
    }
}
