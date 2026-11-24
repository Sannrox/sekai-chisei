//! Source discovery as the `source_discovery` work kind (#3091, ADR 0148,
//! ADR 0149).
//!
//! A Source administrator requests a discovery of a registered Source. The
//! request is a row of its own: a connector runtime whose labels satisfy the
//! Source's placement claims it, runs the connector's discovery with the
//! Source's bound credential, and acknowledges with the discovery in the
//! `sekai.source-discovery/v1` shape plus the bounded samples it read. The
//! requester reads the result back once: reading a finished request deletes
//! it. Nothing here is durable history.
//!
//! A request nobody runs ends visibly. A pending request no runtime claims
//! within [`DISCOVERY_DEADLINE_MS`], or a claimed one whose lease lapsed that
//! long ago, reads as failed `unavailable`. A lapsed lease is otherwise
//! reclaimable by another runtime at a higher generation, and the third
//! lapse fails the request as `lease_expired`. An acknowledge under a stale
//! fence is refused, so a request completes once.
//!
//! Every row expires: an open one [`DISCOVERY_RESULT_TTL_MS`] after it would
//! read as unavailable, a finished one that long after it finished.
//! [`sweep`] deletes expired rows, samples included.

use std::collections::{BTreeMap, BTreeSet};

use sekai_source_sdk::{MAX_DISCOVERY_SAMPLE_ROWS, SourceDiscovery};
use sekai_types::governed_transform::{
    MAX_TRANSFORM_LEASE_EXPIRIES, normalize_transform_claim_ttl_ms, placement_satisfied,
};
use serde::{Deserialize, Serialize};

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::source::{Source, SourceStatus};
use crate::sekai::source_sync::SyncFailure;
use crate::sekai::work_claim::{ClaimError, ClaimRecord, Fence, Hold};

/// How long a request may wait for a runtime, or sit with a lapsed lease,
/// before it reads as failed `unavailable`.
pub const DISCOVERY_DEADLINE_MS: i64 = 120_000;
/// How long a finished request's result is kept for its requester.
pub const DISCOVERY_RESULT_TTL_MS: i64 = 600_000;
/// The lapse that reaches this count fails the request.
pub const MAX_SOURCE_DISCOVERY_LEASE_EXPIRIES: i64 = MAX_TRANSFORM_LEASE_EXPIRIES;
/// The largest discovery document, and separately the largest sample set,
/// an acknowledge may carry.
pub const MAX_DISCOVERY_RESULT_BYTES: usize = 2 * 1024 * 1024;
/// Open requests a runtime lists at once.
pub const MAX_LIST_DISCOVERIES: usize = 200;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_RUNNING: &str = "running";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_FAILED: &str = "failed";

/// One discovery request, as stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceDiscoveryRequest {
    pub discovery_id: String,
    pub namespace: String,
    pub source_id: String,
    pub requested_by: String,
    /// `pending`, `running`, `completed` or `failed`.
    pub status: String,
    /// The [`SyncFailure`] wire name of a failed request.
    pub failure: String,
    pub claim: ClaimRecord,
    /// The runtime that finished the request.
    pub runtime: String,
    /// The `sekai.source-discovery/v1` document of a completed request.
    pub discovery_json: String,
    /// The [`SampledRecordKind`] list of a completed request, as JSON.
    pub samples_json: String,
    pub created_at_ms: i64,
    pub finished_at_ms: i64,
    pub expires_at_ms: i64,
}

/// The bounded sample of one record kind. Cells are source data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampledRecordKind {
    pub record_kind: String,
    /// The connector cannot sample this record kind.
    pub unsupported: bool,
    pub rows: Vec<BTreeMap<String, String>>,
}

/// How a runtime finished a request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryOutcome {
    Completed {
        discovery_json: String,
        samples: Vec<SampledRecordKind>,
    },
    Failed(SyncFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryError {
    NotFound,
    /// The Source is disabled.
    SourceDisabled,
    Owner,
    Placement,
    Claim(ClaimError),
    Invalid(&'static str),
    Store(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("source discovery not found"),
            Self::SourceDisabled => formatter.write_str("source is disabled"),
            Self::Owner => formatter.write_str("claim owner required"),
            Self::Placement => formatter.write_str("runtime labels do not satisfy placement"),
            Self::Claim(error) => error.fmt(formatter),
            Self::Invalid(message) => formatter.write_str(message),
            Self::Store(_) => formatter.write_str("source discovery store unavailable"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<String> for DiscoveryError {
    fn from(error: String) -> Self {
        Self::Store(error)
    }
}

impl SourceDiscoveryRequest {
    /// The claim view of the request's status.
    pub fn hold(&self) -> Hold {
        match self.status.as_str() {
            STATUS_PENDING => Hold::Open,
            STATUS_RUNNING => Hold::Held,
            _ => Hold::Closed,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.hold() == Hold::Closed
    }

    /// When an open request reads as `unavailable`: no runtime claimed it,
    /// or its lease lapsed, [`DISCOVERY_DEADLINE_MS`] ago.
    fn unavailable_at_ms(&self) -> i64 {
        match self.hold() {
            Hold::Open => self.created_at_ms + DISCOVERY_DEADLINE_MS,
            _ => self.claim.expires_at_ms + DISCOVERY_DEADLINE_MS,
        }
    }

    /// Fails an open request nobody runs; `true` when it did.
    fn settle(&mut self, now_ms: i64) -> bool {
        if self.is_finished() || now_ms < self.unavailable_at_ms() {
            return false;
        }
        self.finish(DiscoveryOutcome::Failed(SyncFailure::Unavailable), now_ms);
        true
    }

    fn finish(&mut self, outcome: DiscoveryOutcome, now_ms: i64) {
        match outcome {
            DiscoveryOutcome::Completed {
                discovery_json,
                samples,
            } => {
                self.status = STATUS_COMPLETED.into();
                self.discovery_json = discovery_json;
                // Encoding owned strings cannot fail.
                self.samples_json = serde_json::to_string(&samples).unwrap_or_default();
            }
            DiscoveryOutcome::Failed(failure) => {
                self.status = STATUS_FAILED.into();
                self.failure = failure.wire_name().into();
            }
        }
        self.runtime.clone_from(&self.claim.owner);
        self.finished_at_ms = now_ms;
        self.expires_at_ms = now_ms + DISCOVERY_RESULT_TTL_MS;
    }

    fn refresh_expiry(&mut self) {
        if !self.is_finished() {
            self.expires_at_ms = self.unavailable_at_ms() + DISCOVERY_RESULT_TTL_MS;
        }
    }

    /// The samples of a completed request.
    pub fn samples(&self) -> Vec<SampledRecordKind> {
        serde_json::from_str(&self.samples_json).unwrap_or_default()
    }
}

/// What an edit does with the row.
enum Write {
    Update,
    Delete,
}

/// Requests a discovery of an active Source. The same requester asking
/// again while a request of theirs for that Source is open gets it back.
pub fn request(
    db: &RuntimeDb,
    namespace: &str,
    source_id: &str,
    requested_by: &str,
    now_ms: i64,
) -> Result<SourceDiscoveryRequest, DiscoveryError> {
    let source = db
        .get_source(namespace, source_id)?
        .ok_or(DiscoveryError::NotFound)?;
    if source.status != SourceStatus::Active {
        return Err(DiscoveryError::SourceDisabled);
    }
    let mut fresh = SourceDiscoveryRequest {
        discovery_id: format!("sdisc_{}", uuid::Uuid::new_v4().simple()),
        namespace: namespace.into(),
        source_id: source_id.into(),
        requested_by: requested_by.into(),
        status: STATUS_PENDING.into(),
        created_at_ms: now_ms,
        ..Default::default()
    };
    fresh.refresh_expiry();
    Ok(db.open_source_discovery(&fresh, now_ms)?)
}

/// Open requests in `namespace` a runtime with `labels` may claim now and
/// whose Source `accepts`, with their Sources, oldest first.
pub fn list_claimable(
    db: &RuntimeDb,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    now_ms: i64,
    limit: usize,
    accepts: impl Fn(&Source) -> bool,
) -> Result<Vec<(SourceDiscoveryRequest, Source)>, String> {
    let mut sources: BTreeMap<String, Option<Source>> = BTreeMap::new();
    let mut claimable = Vec::new();
    for request in db.list_open_source_discoveries(namespace, now_ms, MAX_LIST_DISCOVERIES)? {
        if claimable.len() >= limit {
            break;
        }
        if !request
            .claim
            .is_takeable(request.hold(), MAX_SOURCE_DISCOVERY_LEASE_EXPIRIES, now_ms)
        {
            continue;
        }
        if !sources.contains_key(&request.source_id) {
            let source = db.get_source(namespace, &request.source_id)?;
            sources.insert(request.source_id.clone(), source);
        }
        let Some(Some(source)) = sources.get(&request.source_id) else {
            continue;
        };
        if source.status == SourceStatus::Active
            && placement_satisfied(&source.spec.placement, labels)
            && accepts(source)
        {
            claimable.push((request, source.clone()));
        }
    }
    Ok(claimable)
}

/// Claims the request for `owner`, returning it with its Source so the
/// runtime discovers the configuration it was granted under.
pub fn claim(
    db: &RuntimeDb,
    namespace: &str,
    discovery_id: &str,
    owner: &str,
    labels: &BTreeMap<String, String>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<(SourceDiscoveryRequest, Source), DiscoveryError> {
    if owner.trim().is_empty() {
        return Err(DiscoveryError::Owner);
    }
    let current = db
        .get_source_discovery(namespace, discovery_id)?
        .ok_or(DiscoveryError::NotFound)?;
    let source = db
        .get_source(namespace, &current.source_id)?
        .ok_or(DiscoveryError::NotFound)?;
    if source.status != SourceStatus::Active {
        return Err(DiscoveryError::SourceDisabled);
    }
    if !placement_satisfied(&source.spec.placement, labels) {
        return Err(DiscoveryError::Placement);
    }
    let claimed = db.edit_source_discovery(namespace, discovery_id, |request| {
        if request.settle(now_ms) {
            return Ok(Write::Update);
        }
        let hold = request.hold();
        match request
            .claim
            .count_lapse(hold, MAX_SOURCE_DISCOVERY_LEASE_EXPIRIES, now_ms)
        {
            Ok(_) => {}
            Err(ClaimError::LeaseLimit) => {
                // Ends the lapsed claim too, so its fence cannot replay an
                // acknowledge.
                request.finish(DiscoveryOutcome::Failed(SyncFailure::LeaseExpired), now_ms);
                request.claim.fencing_token.clear();
                return Ok(Write::Update);
            }
            Err(error) => return Err(DiscoveryError::Claim(error)),
        }
        request.claim.grant(
            owner,
            normalize_transform_claim_ttl_ms(ttl_ms),
            now_ms,
            |_| uuid::Uuid::new_v4().to_string(),
        );
        request.status = STATUS_RUNNING.into();
        request.refresh_expiry();
        Ok(Write::Update)
    })?;
    match claimed {
        Some(request) if request.status == STATUS_RUNNING => Ok((request, source)),
        Some(request) if request.failure == SyncFailure::LeaseExpired.wire_name() => {
            Err(DiscoveryError::Claim(ClaimError::LeaseLimit))
        }
        _ => Err(DiscoveryError::Claim(ClaimError::Closed)),
    }
}

/// Claims the oldest open request in `namespace` a runtime with `labels`
/// may take and whose Source `accepts`.
pub fn claim_next(
    db: &RuntimeDb,
    namespace: &str,
    owner: &str,
    labels: &BTreeMap<String, String>,
    ttl_ms: i64,
    now_ms: i64,
    accepts: impl Fn(&Source) -> bool,
) -> Result<(SourceDiscoveryRequest, Source), DiscoveryError> {
    let open = list_claimable(db, namespace, labels, now_ms, MAX_LIST_DISCOVERIES, accepts)?;
    for (request, _) in open {
        match claim(
            db,
            namespace,
            &request.discovery_id,
            owner,
            labels,
            ttl_ms,
            now_ms,
        ) {
            Err(DiscoveryError::Claim(_)) => continue,
            claimed => return claimed,
        }
    }
    Err(DiscoveryError::NotFound)
}

/// Extends the live claim `fence`.
pub fn heartbeat(
    db: &RuntimeDb,
    namespace: &str,
    discovery_id: &str,
    fence: Fence<'_>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<SourceDiscoveryRequest, DiscoveryError> {
    db.edit_source_discovery(namespace, discovery_id, |request| {
        let hold = request.hold();
        request
            .claim
            .heartbeat(
                hold,
                fence,
                normalize_transform_claim_ttl_ms(ttl_ms),
                now_ms,
            )
            .map_err(DiscoveryError::Claim)?;
        request.refresh_expiry();
        Ok(Write::Update)
    })?
    .ok_or(DiscoveryError::NotFound)
}

/// Finishes the request under the live `fence`. `replay` is true for a
/// retry under the fence that already finished it, which writes nothing.
pub fn acknowledge(
    db: &RuntimeDb,
    namespace: &str,
    discovery_id: &str,
    fence: Fence<'_>,
    outcome: DiscoveryOutcome,
    now_ms: i64,
) -> Result<(SourceDiscoveryRequest, bool), DiscoveryError> {
    if let DiscoveryOutcome::Completed {
        discovery_json,
        samples,
    } = &outcome
    {
        check_result(discovery_json, samples)?;
    }
    let mut replay = false;
    let request = db
        .edit_source_discovery(namespace, discovery_id, |request| {
            let hold = request.hold();
            if hold == Hold::Closed && request.claim.matches(fence) {
                replay = true;
                return Ok(Write::Update);
            }
            request
                .claim
                .release(hold, fence, now_ms)
                .map_err(DiscoveryError::Claim)?;
            request.finish(outcome, now_ms);
            Ok(Write::Update)
        })?
        .ok_or(DiscoveryError::NotFound)?;
    Ok((request, replay))
}

/// A completed result must be a valid `sekai.source-discovery/v1` document
/// with bounded samples of the record kinds it lists.
fn check_result(discovery_json: &str, samples: &[SampledRecordKind]) -> Result<(), DiscoveryError> {
    if discovery_json.len() > MAX_DISCOVERY_RESULT_BYTES {
        return Err(DiscoveryError::Invalid("discovery is too large"));
    }
    let discovery: SourceDiscovery = serde_json::from_str(discovery_json)
        .map_err(|_| DiscoveryError::Invalid("discovery is not a source discovery document"))?;
    discovery
        .validate()
        .map_err(|_| DiscoveryError::Invalid("discovery is not a valid source discovery"))?;
    let kinds: BTreeSet<&str> = discovery
        .record_kinds
        .iter()
        .map(|kind| kind.record_kind.as_str())
        .collect();
    let mut seen = BTreeSet::new();
    let mut bytes = 0usize;
    for sample in samples {
        if !kinds.contains(sample.record_kind.as_str()) || !seen.insert(&sample.record_kind) {
            return Err(DiscoveryError::Invalid(
                "a sample must name a discovered record kind once",
            ));
        }
        if sample.rows.len() > MAX_DISCOVERY_SAMPLE_ROWS
            || (sample.unsupported && !sample.rows.is_empty())
        {
            return Err(DiscoveryError::Invalid(
                "a sample exceeds the plane's bound",
            ));
        }
        bytes += sample
            .rows
            .iter()
            .flat_map(|row| row.iter())
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>();
    }
    if bytes > MAX_DISCOVERY_RESULT_BYTES {
        return Err(DiscoveryError::Invalid("samples are too large"));
    }
    Ok(())
}

/// Reads the request for its requester. A finished request is deleted by
/// the read, so its result is handed out once; an open one stays.
pub fn take(
    db: &RuntimeDb,
    namespace: &str,
    discovery_id: &str,
    requested_by: &str,
    now_ms: i64,
) -> Result<SourceDiscoveryRequest, DiscoveryError> {
    db.edit_source_discovery(namespace, discovery_id, |request| {
        // Another requester's discovery reads as missing.
        if request.requested_by != requested_by {
            return Err(DiscoveryError::NotFound);
        }
        request.settle(now_ms);
        if request.is_finished() {
            Ok(Write::Delete)
        } else {
            Ok(Write::Update)
        }
    })?
    .ok_or(DiscoveryError::NotFound)
}

/// Deletes every request past its expiry; returns how many.
pub fn sweep(db: &RuntimeDb, now_ms: i64) -> Result<u64, String> {
    db.sweep_source_discoveries(now_ms)
}

const COLUMNS: &str = "discovery_id, namespace, source_id, requested_by, status, failure, \
     claim_owner, claim_generation, claim_fencing_token, claim_expires_at_ms, \
     claim_lease_expiries, runtime, discovery_json, samples_json, created_at_ms, \
     finished_at_ms, expires_at_ms";

const INSERT_SQL: &str = "INSERT INTO sekai_source_discoveries (discovery_id, namespace, \
     source_id, requested_by, status, created_at_ms, expires_at_ms) \
     VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING";

const UPDATE_SQL: &str = "UPDATE sekai_source_discoveries SET status = $1, failure = $2, \
     claim_owner = $3, claim_generation = $4, claim_fencing_token = $5, \
     claim_expires_at_ms = $6, claim_lease_expiries = $7, runtime = $8, \
     discovery_json = $9, samples_json = $10, finished_at_ms = $11, expires_at_ms = $12 \
     WHERE namespace = $13 AND discovery_id = $14";

const DELETE_SQL: &str =
    "DELETE FROM sekai_source_discoveries WHERE namespace = $1 AND discovery_id = $2";

/// Open requests a runtime could take: pending ones not yet past the
/// deadline, and claimed ones whose lease lapsed less than the deadline ago.
const OPEN_SQL: &str = "SELECT discovery_id, namespace, source_id, requested_by, status, \
     failure, claim_owner, claim_generation, claim_fencing_token, claim_expires_at_ms, \
     claim_lease_expiries, runtime, discovery_json, samples_json, created_at_ms, \
     finished_at_ms, expires_at_ms FROM sekai_source_discoveries \
     WHERE namespace = $1 AND ((status = 'pending' AND created_at_ms > CAST($2 AS BIGINT) - CAST($3 AS BIGINT)) \
       OR (status = 'running' AND claim_expires_at_ms <= CAST($2 AS BIGINT) \
         AND claim_expires_at_ms > CAST($2 AS BIGINT) - CAST($3 AS BIGINT))) \
     ORDER BY created_at_ms, discovery_id LIMIT $4";

const OPEN_FOR_SQL: &str = "SELECT discovery_id, namespace, source_id, requested_by, status, \
     failure, claim_owner, claim_generation, claim_fencing_token, claim_expires_at_ms, \
     claim_lease_expiries, runtime, discovery_json, samples_json, created_at_ms, \
     finished_at_ms, expires_at_ms FROM sekai_source_discoveries \
     WHERE namespace = $1 AND source_id = $2 AND requested_by = $3 \
       AND status IN ('pending', 'running')";

const SWEEP_SQL: &str = "DELETE FROM sekai_source_discoveries WHERE expires_at_ms <= $1";

const SQLITE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sekai_source_discoveries (
    discovery_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    source_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL,
    failure TEXT NOT NULL DEFAULT '',
    claim_owner TEXT NOT NULL DEFAULT '',
    claim_generation INTEGER NOT NULL DEFAULT 0,
    claim_fencing_token TEXT NOT NULL DEFAULT '',
    claim_expires_at_ms INTEGER NOT NULL DEFAULT 0,
    claim_lease_expiries INTEGER NOT NULL DEFAULT 0,
    runtime TEXT NOT NULL DEFAULT '',
    discovery_json TEXT NOT NULL DEFAULT '',
    samples_json TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER NOT NULL DEFAULT 0,
    expires_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS sekai_source_discoveries_open
    ON sekai_source_discoveries (namespace, source_id, requested_by)
    WHERE status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS sekai_source_discoveries_claimable
    ON sekai_source_discoveries (namespace, status, created_at_ms, discovery_id);
CREATE INDEX IF NOT EXISTS sekai_source_discoveries_expiry
    ON sekai_source_discoveries (expires_at_ms);
";

fn sqlite_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<SourceDiscoveryRequest> {
    Ok(SourceDiscoveryRequest {
        discovery_id: row.get(0)?,
        namespace: row.get(1)?,
        source_id: row.get(2)?,
        requested_by: row.get(3)?,
        status: row.get(4)?,
        failure: row.get(5)?,
        claim: ClaimRecord {
            owner: row.get(6)?,
            generation: row.get(7)?,
            fencing_token: row.get(8)?,
            expires_at_ms: row.get(9)?,
            lease_expiries: row.get(10)?,
        },
        runtime: row.get(11)?,
        discovery_json: row.get(12)?,
        samples_json: row.get(13)?,
        created_at_ms: row.get(14)?,
        finished_at_ms: row.get(15)?,
        expires_at_ms: row.get(16)?,
    })
}

fn postgres_request(row: &postgres::Row) -> SourceDiscoveryRequest {
    SourceDiscoveryRequest {
        discovery_id: row.get(0),
        namespace: row.get(1),
        source_id: row.get(2),
        requested_by: row.get(3),
        status: row.get(4),
        failure: row.get(5),
        claim: ClaimRecord {
            owner: row.get(6),
            generation: row.get(7),
            fencing_token: row.get(8),
            expires_at_ms: row.get(9),
            lease_expiries: row.get(10),
        },
        runtime: row.get(11),
        discovery_json: row.get(12),
        samples_json: row.get(13),
        created_at_ms: row.get(14),
        finished_at_ms: row.get(15),
        expires_at_ms: row.get(16),
    }
}

fn store(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn list_limit(limit: usize) -> i64 {
    i64::try_from(limit.min(MAX_LIST_DISCOVERIES)).unwrap_or(0)
}

impl SekaiDb {
    pub(crate) fn migrate_source_discoveries(&self) -> Result<(), String> {
        self.conn().execute_batch(SQLITE_SCHEMA).map_err(store)
    }

    /// Inserts `fresh` unless the requester has an open request for the
    /// Source; one that should already read as unavailable is failed first.
    /// Returns the open request.
    pub fn open_source_discovery(
        &self,
        fresh: &SourceDiscoveryRequest,
        now_ms: i64,
    ) -> Result<SourceDiscoveryRequest, String> {
        use rusqlite::OptionalExtension;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(store)?;
        let key = rusqlite::params![fresh.namespace, fresh.source_id, fresh.requested_by];
        let existing = tx
            .query_row(OPEN_FOR_SQL, key, sqlite_request)
            .optional()
            .map_err(store)?;
        if let Some(mut existing) = existing {
            if !existing.settle(now_ms) {
                return Ok(existing);
            }
            sqlite_update(&tx, &existing)?;
        }
        tx.execute(
            INSERT_SQL,
            rusqlite::params![
                fresh.discovery_id,
                fresh.namespace,
                fresh.source_id,
                fresh.requested_by,
                fresh.status,
                fresh.created_at_ms,
                fresh.expires_at_ms
            ],
        )
        .map_err(store)?;
        let open = tx
            .query_row(OPEN_FOR_SQL, key, sqlite_request)
            .map_err(store)?;
        tx.commit().map_err(store)?;
        Ok(open)
    }

    pub fn get_source_discovery(
        &self,
        namespace: &str,
        discovery_id: &str,
    ) -> Result<Option<SourceDiscoveryRequest>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_source_discoveries \
                     WHERE namespace = $1 AND discovery_id = $2"
                ),
                rusqlite::params![namespace, discovery_id],
                sqlite_request,
            )
            .optional()
            .map_err(store)
    }

    pub fn list_open_source_discoveries(
        &self,
        namespace: &str,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<SourceDiscoveryRequest>, String> {
        let conn = self.conn();
        let mut statement = conn.prepare(OPEN_SQL).map_err(store)?;
        let rows = statement
            .query_map(
                rusqlite::params![namespace, now_ms, DISCOVERY_DEADLINE_MS, list_limit(limit)],
                sqlite_request,
            )
            .map_err(store)?;
        rows.map(|row| row.map_err(store)).collect()
    }

    /// Reads the request, lets `change` edit it, and writes or deletes it
    /// as `change` says, in one immediate transaction. An error writes
    /// nothing. `None` when the request does not exist.
    fn edit_source_discovery(
        &self,
        namespace: &str,
        discovery_id: &str,
        change: impl FnOnce(&mut SourceDiscoveryRequest) -> Result<Write, DiscoveryError>,
    ) -> Result<Option<SourceDiscoveryRequest>, DiscoveryError> {
        use rusqlite::OptionalExtension;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(store)?;
        let Some(mut request) = tx
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_source_discoveries \
                     WHERE namespace = $1 AND discovery_id = $2"
                ),
                rusqlite::params![namespace, discovery_id],
                sqlite_request,
            )
            .optional()
            .map_err(store)?
        else {
            return Ok(None);
        };
        match change(&mut request)? {
            Write::Update => sqlite_update(&tx, &request)?,
            Write::Delete => {
                tx.execute(DELETE_SQL, rusqlite::params![namespace, discovery_id])
                    .map_err(store)?;
            }
        }
        tx.commit().map_err(store)?;
        Ok(Some(request))
    }

    pub fn sweep_source_discoveries(&self, now_ms: i64) -> Result<u64, String> {
        self.conn()
            .execute(SWEEP_SQL, rusqlite::params![now_ms])
            .map(|deleted| deleted as u64)
            .map_err(store)
    }
}

fn sqlite_update(
    tx: &rusqlite::Transaction<'_>,
    request: &SourceDiscoveryRequest,
) -> Result<(), String> {
    tx.execute(
        UPDATE_SQL,
        rusqlite::params![
            request.status,
            request.failure,
            request.claim.owner,
            request.claim.generation,
            request.claim.fencing_token,
            request.claim.expires_at_ms,
            request.claim.lease_expiries,
            request.runtime,
            request.discovery_json,
            request.samples_json,
            request.finished_at_ms,
            request.expires_at_ms,
            request.namespace,
            request.discovery_id
        ],
    )
    .map(|_| ())
    .map_err(store)
}

fn postgres_update(
    tx: &mut postgres::Transaction<'_>,
    request: &SourceDiscoveryRequest,
) -> Result<(), String> {
    tx.execute(
        UPDATE_SQL,
        &[
            &request.status,
            &request.failure,
            &request.claim.owner,
            &request.claim.generation,
            &request.claim.fencing_token,
            &request.claim.expires_at_ms,
            &request.claim.lease_expiries,
            &request.runtime,
            &request.discovery_json,
            &request.samples_json,
            &request.finished_at_ms,
            &request.expires_at_ms,
            &request.namespace,
            &request.discovery_id,
        ],
    )
    .map(|_| ())
    .map_err(store)
}

impl PostgresDb {
    /// See [`SekaiDb::open_source_discovery`]. The insert and the lookup
    /// race only on the open index, which `ON CONFLICT DO NOTHING` absorbs.
    pub fn open_source_discovery(
        &self,
        fresh: &SourceDiscoveryRequest,
        now_ms: i64,
    ) -> Result<SourceDiscoveryRequest, String> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(store)?;
        let key: [&(dyn postgres::types::ToSql + Sync); 3] =
            [&fresh.namespace, &fresh.source_id, &fresh.requested_by];
        let existing = tx
            .query_opt(&format!("{OPEN_FOR_SQL} FOR UPDATE"), &key)
            .map_err(store)?
            .as_ref()
            .map(postgres_request);
        if let Some(mut existing) = existing {
            if !existing.settle(now_ms) {
                return Ok(existing);
            }
            postgres_update(&mut tx, &existing)?;
        }
        tx.execute(
            INSERT_SQL,
            &[
                &fresh.discovery_id,
                &fresh.namespace,
                &fresh.source_id,
                &fresh.requested_by,
                &fresh.status,
                &fresh.created_at_ms,
                &fresh.expires_at_ms,
            ],
        )
        .map_err(store)?;
        let open = tx.query_one(OPEN_FOR_SQL, &key).map_err(store)?;
        tx.commit().map_err(store)?;
        Ok(postgres_request(&open))
    }

    pub fn get_source_discovery(
        &self,
        namespace: &str,
        discovery_id: &str,
    ) -> Result<Option<SourceDiscoveryRequest>, String> {
        Ok(self
            .connection()?
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_source_discoveries \
                     WHERE namespace = $1 AND discovery_id = $2"
                ),
                &[&namespace, &discovery_id],
            )
            .map_err(store)?
            .as_ref()
            .map(postgres_request))
    }

    pub fn list_open_source_discoveries(
        &self,
        namespace: &str,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<SourceDiscoveryRequest>, String> {
        Ok(self
            .connection()?
            .query(
                OPEN_SQL,
                &[
                    &namespace,
                    &now_ms,
                    &DISCOVERY_DEADLINE_MS,
                    &list_limit(limit),
                ],
            )
            .map_err(store)?
            .iter()
            .map(postgres_request)
            .collect())
    }

    /// See [`SekaiDb::edit_source_discovery`]; the row is locked.
    fn edit_source_discovery(
        &self,
        namespace: &str,
        discovery_id: &str,
        change: impl FnOnce(&mut SourceDiscoveryRequest) -> Result<Write, DiscoveryError>,
    ) -> Result<Option<SourceDiscoveryRequest>, DiscoveryError> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction().map_err(store)?;
        let Some(mut request) = tx
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_source_discoveries \
                     WHERE namespace = $1 AND discovery_id = $2 FOR UPDATE"
                ),
                &[&namespace, &discovery_id],
            )
            .map_err(store)?
            .as_ref()
            .map(postgres_request)
        else {
            return Ok(None);
        };
        match change(&mut request)? {
            Write::Update => postgres_update(&mut tx, &request)?,
            Write::Delete => {
                tx.execute(DELETE_SQL, &[&namespace, &discovery_id])
                    .map_err(store)?;
            }
        }
        tx.commit().map_err(store)?;
        Ok(Some(request))
    }

    pub fn sweep_source_discoveries(&self, now_ms: i64) -> Result<u64, String> {
        self.connection()?
            .execute(SWEEP_SQL, &[&now_ms])
            .map_err(store)
    }
}

impl RuntimeDb {
    pub fn open_source_discovery(
        &self,
        fresh: &SourceDiscoveryRequest,
        now_ms: i64,
    ) -> Result<SourceDiscoveryRequest, String> {
        match self {
            Self::Sqlite(db) => db.open_source_discovery(fresh, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.open_source_discovery(fresh, now_ms))
            }
        }
    }

    pub fn get_source_discovery(
        &self,
        namespace: &str,
        discovery_id: &str,
    ) -> Result<Option<SourceDiscoveryRequest>, String> {
        match self {
            Self::Sqlite(db) => db.get_source_discovery(namespace, discovery_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_source_discovery(namespace, discovery_id)
            }),
        }
    }

    pub fn list_open_source_discoveries(
        &self,
        namespace: &str,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<SourceDiscoveryRequest>, String> {
        match self {
            Self::Sqlite(db) => db.list_open_source_discoveries(namespace, now_ms, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_open_source_discoveries(namespace, now_ms, limit)
            }),
        }
    }

    fn edit_source_discovery(
        &self,
        namespace: &str,
        discovery_id: &str,
        change: impl FnOnce(&mut SourceDiscoveryRequest) -> Result<Write, DiscoveryError>,
    ) -> Result<Option<SourceDiscoveryRequest>, DiscoveryError> {
        match self {
            Self::Sqlite(db) => db.edit_source_discovery(namespace, discovery_id, change),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.edit_source_discovery(namespace, discovery_id, change)
            }),
        }
    }

    pub fn sweep_source_discoveries(&self, now_ms: i64) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.sweep_source_discoveries(now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.sweep_source_discoveries(now_ms))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::source::{self, tests::github};
    use sekai_source_sdk::{DiscoveredColumn, DiscoveredRecordKind, SOURCE_DISCOVERY_VERSION};

    const TTL: i64 = 1_000;

    fn labels() -> BTreeMap<String, String> {
        BTreeMap::from([("zone".into(), "eu".into())])
    }

    /// A namespace with one GitHub Source, `repo`, placed in zone `a`.
    fn setup(db: &RuntimeDb) -> String {
        let namespace = format!("ns-{}", uuid::Uuid::new_v4().simple());
        source::put(db, &github(&namespace, "repo", "acme/repo")).unwrap();
        namespace
    }

    fn document() -> String {
        serde_json::to_string(&SourceDiscovery {
            contract_version: SOURCE_DISCOVERY_VERSION.into(),
            source: "postgres.table".into(),
            record_kinds: vec![DiscoveredRecordKind {
                record_kind: "customer".into(),
                schema_revision: "1".into(),
                columns: vec![DiscoveredColumn {
                    name: "id".into(),
                    data_type: "text".into(),
                    nullable: false,
                    profile: None,
                }],
                key_candidates: vec![vec!["id".into()]],
                references: Vec::new(),
                value_findings: Vec::new(),
            }],
        })
        .unwrap()
    }

    fn completed(rows: usize) -> DiscoveryOutcome {
        DiscoveryOutcome::Completed {
            discovery_json: document(),
            samples: vec![SampledRecordKind {
                record_kind: "customer".into(),
                unsupported: false,
                rows: (0..rows)
                    .map(|n| BTreeMap::from([("id".into(), n.to_string())]))
                    .collect(),
            }],
        }
    }

    fn fence(request: &SourceDiscoveryRequest) -> Fence<'_> {
        Fence {
            owner: &request.claim.owner,
            generation: request.claim.generation,
            token: &request.claim.fencing_token,
        }
    }

    #[test]
    fn a_result_is_completed_once_and_read_once_by_its_requester() {
        let db = RuntimeDb::memory();
        let ns = setup(&db);
        let asked = request(&db, &ns, "repo", "alice", 0).unwrap();
        assert_eq!(asked.status, STATUS_PENDING);
        // Asking again while it is open returns the same request.
        assert_eq!(
            request(&db, &ns, "repo", "alice", 10).unwrap().discovery_id,
            asked.discovery_id
        );
        assert_ne!(
            request(&db, &ns, "repo", "bob", 10).unwrap().discovery_id,
            asked.discovery_id
        );
        let id = &asked.discovery_id;
        assert_eq!(
            claim(&db, &ns, id, "rt", &BTreeMap::new(), TTL, 100).unwrap_err(),
            DiscoveryError::Placement
        );
        let (held, source) = claim(&db, &ns, id, "rt", &labels(), TTL, 100).unwrap();
        assert_eq!(source.source_id, "repo");
        assert_eq!(held.status, STATUS_RUNNING);
        // An open read leaves it in place.
        assert_eq!(
            take(&db, &ns, id, "alice", 200).unwrap().status,
            STATUS_RUNNING
        );

        assert_eq!(
            acknowledge(
                &db,
                &ns,
                id,
                fence(&held),
                completed(MAX_DISCOVERY_SAMPLE_ROWS + 1),
                300
            )
            .unwrap_err(),
            DiscoveryError::Invalid("a sample exceeds the plane's bound")
        );
        let (done, replay) = acknowledge(&db, &ns, id, fence(&held), completed(2), 300).unwrap();
        assert!(!replay);
        assert_eq!(done.status, STATUS_COMPLETED);
        assert_eq!(done.runtime, "rt");
        let (_, replay) = acknowledge(&db, &ns, id, fence(&held), completed(2), 310).unwrap();
        assert!(replay, "a retried acknowledge writes nothing");

        assert_eq!(
            take(&db, &ns, id, "bob", 400).unwrap_err(),
            DiscoveryError::NotFound
        );
        let read = take(&db, &ns, id, "alice", 400).unwrap();
        assert_eq!(read.discovery_json, document());
        assert_eq!(read.samples().first().map(|kind| kind.rows.len()), Some(2));
        assert_eq!(
            take(&db, &ns, id, "alice", 410).unwrap_err(),
            DiscoveryError::NotFound,
            "a result is handed out once"
        );
    }

    #[test]
    fn a_request_nobody_runs_reads_as_unavailable() {
        let db = RuntimeDb::memory();
        let ns = setup(&db);
        let pending = request(&db, &ns, "repo", "alice", 0).unwrap();
        assert_eq!(
            take(
                &db,
                &ns,
                &pending.discovery_id,
                "alice",
                DISCOVERY_DEADLINE_MS - 1
            )
            .unwrap()
            .status,
            STATUS_PENDING
        );
        let late = take(
            &db,
            &ns,
            &pending.discovery_id,
            "alice",
            DISCOVERY_DEADLINE_MS,
        )
        .unwrap();
        assert_eq!(
            (late.status.as_str(), late.failure.as_str()),
            (STATUS_FAILED, "unavailable")
        );

        // A runtime killed mid-discovery, with no runtime to take over.
        let asked = request(&db, &ns, "repo", "alice", 0).unwrap();
        let (held, _) = claim(&db, &ns, &asked.discovery_id, "rt", &labels(), TTL, 0).unwrap();
        let lapsed_at = held.claim.expires_at_ms;
        assert!(
            list_claimable(&db, &ns, &labels(), lapsed_at, 10, |_| true)
                .unwrap()
                .len()
                == 1,
            "a lapsed lease is offered to another runtime"
        );
        // A new request after the deadline replaces the stale open one.
        let next = request(&db, &ns, "repo", "alice", lapsed_at + DISCOVERY_DEADLINE_MS).unwrap();
        assert_ne!(next.discovery_id, asked.discovery_id);
        let stale = db
            .get_source_discovery(&ns, &asked.discovery_id)
            .unwrap()
            .unwrap();
        assert_eq!(stale.failure, "unavailable");
        assert!(
            list_claimable(
                &db,
                &ns,
                &labels(),
                lapsed_at + DISCOVERY_DEADLINE_MS,
                10,
                |_| true
            )
            .unwrap()
            .iter()
            .all(|(open, _)| open.discovery_id == next.discovery_id)
        );
    }

    #[test]
    fn expired_requests_are_swept() {
        let db = RuntimeDb::memory();
        let ns = setup(&db);
        let asked = request(&db, &ns, "repo", "alice", 0).unwrap();
        assert_eq!(sweep(&db, asked.expires_at_ms - 1).unwrap(), 0);
        assert_eq!(sweep(&db, asked.expires_at_ms).unwrap(), 1);
        assert!(
            db.get_source_discovery(&ns, &asked.discovery_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_invalid_document_is_refused() {
        let db = RuntimeDb::memory();
        let ns = setup(&db);
        let asked = request(&db, &ns, "repo", "alice", 0).unwrap();
        let (held, _) = claim(&db, &ns, &asked.discovery_id, "rt", &labels(), TTL, 0).unwrap();
        let refused = acknowledge(
            &db,
            &ns,
            &asked.discovery_id,
            fence(&held),
            DiscoveryOutcome::Completed {
                discovery_json: "{}".into(),
                samples: Vec::new(),
            },
            10,
        );
        assert_eq!(
            refused.unwrap_err(),
            DiscoveryError::Invalid("discovery is not a source discovery document")
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_open_requests_dedupe_and_read_once() {
        let db = crate::sekai::work_claim_conformance::postgres();
        let ns = setup(&db);
        let asked = request(&db, &ns, "repo", "alice", 0).unwrap();
        assert_eq!(
            request(&db, &ns, "repo", "alice", 1).unwrap().discovery_id,
            asked.discovery_id
        );
        let open = list_claimable(&db, &ns, &labels(), 1, 10, |_| true).unwrap();
        assert_eq!(open.len(), 1);
        let (held, _) = claim(&db, &ns, &asked.discovery_id, "rt", &labels(), TTL, 2).unwrap();
        acknowledge(&db, &ns, &asked.discovery_id, fence(&held), completed(1), 3).unwrap();
        assert_eq!(
            take(&db, &ns, &asked.discovery_id, "alice", 4)
                .unwrap()
                .status,
            STATUS_COMPLETED
        );
        assert!(
            db.get_source_discovery(&ns, &asked.discovery_id)
                .unwrap()
                .is_none()
        );
    }
}
