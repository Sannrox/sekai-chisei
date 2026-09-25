//! Fail-closed dual-read of EvaluateObjectSet against a tagged object-log library.
//!
//! `SEKAI_OBJECT_INDEX_DUAL_READ` compares SQL hop engines. This gate compares
//! the SQL projection to in-process mikura `ObjectSet::evaluate` (ADR 0081).

use crate::domain::Object;
use crate::sekai::object_security::ObjectSecurityPolicy;
use crate::sekai::object_set::{ObjectSetAggregation, ObjectSetDescriptor};
use crate::sekai::object_type_index::ObjectTypeIndexMember;
use mikura::{
    Aggregate, EvaluateRequest, EvaluateResponse, Hop, LocalCompute, ObjectRecord, ObjectSet,
    PropertyAcl, Store,
};
use std::collections::{BTreeSet, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub const DUAL_READ_ENV: &str = "SEKAI_OBJECT_LOG_DUAL_READ";
pub const LOG_PATH_ENV: &str = "SEKAI_OBJECT_LOG";
pub const SAMPLE_ENV: &str = "SEKAI_OBJECT_LOG_DUAL_READ_SAMPLE";
const DEFAULT_SAMPLE_N: u32 = 32;

static SAMPLE_TICK: AtomicU64 = AtomicU64::new(0);

/// #1106: one process-scoped `Store` handle reused for every admit instead
/// of a fresh `Store::open` — a full read of the on-disk log plus a replay
/// of every record into memory — on every single admitted mutation.
///
/// Keyed by path rather than a bare `Option<Store>` so a changed
/// `SEKAI_OBJECT_LOG` (or, in tests, a new `with_test_log_path` override)
/// transparently reopens instead of silently serving state read from a
/// different log. [`ensure_admitted_object_in_configured_log`] and
/// [`apply_admitted_object_to_log`] are the only production writers of a
/// configured object-log path, and they write through this handle, so its
/// in-memory state tracks the file. #1110: the dual-read canary reads the
/// same `SEKAI_OBJECT_LOG` through this handle instead of a `Store::open`
/// per sample. The handle also records the file's length, modification
/// time, and superblock digest after each use and reopens when any differs,
/// so a committed write that did not go through it (an operator tool, a test
/// fixture) is never served from stale memory.
static OBJECT_LOG_STORE: OnceLock<Mutex<Option<CachedObjectLogStore>>> = OnceLock::new();

struct CachedObjectLogStore {
    path: PathBuf,
    store: Store,
    stamp: Option<LogStamp>,
}

/// Bytes at the head of the log that hold mikura's superblock. The pinned
/// tag writes a 4096-byte superblock at offset 0 carrying the committed page
/// count, rewritten on every commit.
const SUPERBLOCK_BYTES: usize = 4096;

/// Length, modification time, and a digest of the superblock. The superblock
/// digest changes on every commit, so a write that reuses a torn tail page's
/// length within one coarse modification-time tick is still detected.
/// Modification time is optional: a filesystem without it keeps the cache
/// on length and superblock digest instead of reopening on every call.
type LogStamp = (u64, Option<std::time::SystemTime>, u64);

fn log_stamp(path: &Path) -> Option<LogStamp> {
    use std::hash::{Hash, Hasher};
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let mut head = Vec::with_capacity(SUPERBLOCK_BYTES);
    file.by_ref()
        .take(SUPERBLOCK_BYTES as u64)
        .read_to_end(&mut head)
        .ok()?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    head.hash(&mut hasher);
    Some((metadata.len(), metadata.modified().ok(), hasher.finish()))
}

/// Runs `body` against a `Store` for `path`, reusing the cached handle when
/// it already wraps `path` and opening (creating the log and its parent
/// directory if `path` does not exist yet) otherwise. Holds the cache lock
/// for the whole check-then-use sequence so a concurrent caller can never
/// observe a handle for the wrong path.
///
/// Evicts the cache whenever `body` returns `Err`: mikura's writer is not
/// failure-atomic (a partial page or superblock write on error can leave
/// its cursor inconsistent with what actually landed on disk), so a failed
/// operation must not leave that handle cached for a later call to keep
/// writing through. The next call reopens and re-derives the correct
/// cursor from disk instead, exactly as every call did before this cache
/// existed.
fn with_object_log_store_cache<R>(
    cache: &Mutex<Option<CachedObjectLogStore>>,
    path: &Path,
    body: impl FnOnce(&mut Store) -> Result<R, String>,
) -> Result<R, String> {
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let stale = match guard.as_ref() {
        Some(cached) => {
            cached.path != path || cached.stamp.is_none() || cached.stamp != log_stamp(path)
        }
        None => true,
    };
    if stale {
        #[cfg(test)]
        OBJECT_LOG_STORE_OPENS.with(|opens| opens.set(opens.get().saturating_add(1)));
        let store = if path.exists() {
            Store::open(path)?
        } else {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            Store::create(path)?
        };
        *guard = Some(CachedObjectLogStore {
            path: path.to_path_buf(),
            store,
            stamp: None,
        });
    }
    let cached = guard.as_mut().expect("cache populated above");
    let result = body(&mut cached.store);
    if result.is_err() {
        *guard = None;
    } else {
        cached.stamp = log_stamp(path);
    }
    result
}

fn with_cached_object_log_store<R>(
    path: &Path,
    body: impl FnOnce(&mut Store) -> Result<R, String>,
) -> Result<R, String> {
    let cache = OBJECT_LOG_STORE.get_or_init(|| Mutex::new(None));
    with_object_log_store_cache(cache, path, body)
}

#[cfg(test)]
thread_local! {
    static TEST_LOG_PATH: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static TEST_LOG_HOST: std::cell::RefCell<Option<crate::sekai::object_log_host::ObjectLogHost>> =
        const { std::cell::RefCell::new(None) };
    static FAIL_NEXT_INGEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OBJECT_LOG_STORE_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub fn fail_next_ingest() {
    FAIL_NEXT_INGEST.with(|flag| flag.set(true));
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectLogDualRead {
    pub enabled: bool,
    pub log_path: Option<PathBuf>,
    /// Compare one of `sample_n` armed requests. `1` is CI. Unset soak
    /// defaults to 32 so enabling the flag is not a per-request Store open.
    pub sample_n: u32,
}

impl ObjectLogDualRead {
    pub fn from_env() -> Self {
        Self::resolve(
            env::var(DUAL_READ_ENV).ok(),
            env::var(SAMPLE_ENV).ok(),
            env::var(LOG_PATH_ENV).ok(),
            env::var(crate::sekai::object_log_host::HOST_ENV).ok(),
        )
    }

    /// Resolves the dual-read settings. A configured object-log host owns
    /// the log (ADR 0088), so the canary never opens a local log then, even
    /// when `SEKAI_OBJECT_LOG` is also set (#1202); admits refuse that
    /// combination outright.
    pub fn resolve(
        dual_read: Option<String>,
        sample: Option<String>,
        log_path: Option<String>,
        host: Option<String>,
    ) -> Self {
        let enabled = dual_read.unwrap_or_default() == "1";
        let sample_n = sample
            .and_then(|value| value.parse().ok())
            .unwrap_or(if enabled { DEFAULT_SAMPLE_N } else { 1 });
        let host_configured = host.is_some_and(|value| !value.trim().is_empty());
        let log_path = log_path
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty() && !host_configured)
            .map(PathBuf::from);
        Self {
            enabled,
            log_path,
            sample_n: sample_n.max(1),
        }
    }

    pub(crate) fn take_sample(&self) -> bool {
        let n = u64::from(self.sample_n.max(1));
        SAMPLE_TICK
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(n)
    }
}

/// Whether this evaluate should load `active_object_policy` and open the
/// object-log Store.
///
/// Sample first so unsampled requests pay neither cost. After a hit, skip
/// unexpressible grammar before any policy fetch. The Store read stays inside
/// [`compare_sql_to_log_path`] on the canary only.
pub fn should_fetch_canary_policies(
    config: &ObjectLogDualRead,
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    max_rows_scanned: i32,
) -> bool {
    if !config.enabled || max_rows_scanned <= 0 {
        return false;
    }
    if !config.take_sample() {
        return false;
    }
    !matches!(
        map_evaluate_request(descriptor, hops, aggregation, PropertyAcl::allow_all()),
        Err(ObjectLogCompareError::Unsupported(_))
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectLogCompareError {
    Disabled,
    Unbounded,
    GrantNarrowed,
    MissingLog,
    Unsupported(&'static str),
    Evaluate(String),
    Mismatch {
        sql_roots: usize,
        sql_sum: i64,
        log: EvaluateResponse,
    },
}

impl ObjectLogCompareError {
    pub fn message(&self) -> String {
        match self {
            Self::Disabled => "object-log dual-read is off".into(),
            Self::Unbounded => "object-log dual-read requires max_rows_scanned".into(),
            Self::GrantNarrowed => {
                "object-log dual-read soak is allow-all-only; property grants narrow visibility"
                    .into()
            }
            Self::MissingLog => {
                "object-log dual-read requires a local SEKAI_OBJECT_LOG to an existing mikura \
                 log, and runs only without SEKAI_OBJECT_LOG_HOST"
                    .into()
            }
            Self::Unsupported(reason) => {
                format!("object-log dual-read cannot map request: {reason}")
            }
            Self::Evaluate(error) => format!("object-log evaluate failed: {error}"),
            Self::Mismatch {
                sql_roots,
                sql_sum,
                log,
            } => format!(
                "object-log dual-read mismatch: sql roots={sql_roots} sum={sql_sum} log roots={} sum={}",
                log.two_hop_count, log.sum_amount
            ),
        }
    }
}

pub fn map_evaluate_request(
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    acl: PropertyAcl,
) -> Result<EvaluateRequest, ObjectLogCompareError> {
    if !descriptor.property_filters.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "property filters are not expressible on the tagged object-log evaluate API",
        ));
    }
    if hops.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "object-log evaluate requires at least one hop",
        ));
    }
    if !aggregation.group_by.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "group_by buckets are not expressible on the tagged object-log evaluate API",
        ));
    }
    let function = aggregation.function.to_ascii_lowercase();
    if function != "sum" && function != "count" {
        return Err(ObjectLogCompareError::Unsupported(
            "object-log evaluate compares count or sum only",
        ));
    }
    let sum_property = if aggregation.property.is_empty() {
        if function == "count" {
            String::new()
        } else {
            return Err(ObjectLogCompareError::Unsupported(
                "sum compare requires aggregation.property",
            ));
        }
    } else {
        aggregation.property.clone()
    };
    if function == "sum" && sum_property.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "sum compare requires aggregation.property",
        ));
    }
    let sum_kind = hops
        .last()
        .map(|hop| hop.far_kind.clone())
        .unwrap_or_else(|| descriptor.kind.clone());
    for hop in hops {
        let direction = hop.direction.trim();
        if !direction.is_empty() && !direction.eq_ignore_ascii_case("outgoing") {
            return Err(ObjectLogCompareError::Unsupported(
                "hop direction is not expressible on the tagged object-log evaluate API",
            ));
        }
    }
    Ok(EvaluateRequest {
        root_kind: descriptor.kind.clone(),
        hops: hops
            .iter()
            .map(|hop| Hop {
                far_kind: hop.far_kind.clone(),
                join_property: hop.join_property.clone(),
                // v0.1 joined far rows whose join property names the frontier
                // key; `incoming: false` keeps that direction.
                ..Hop::default()
            })
            .collect(),
        sum_kind,
        sum_property,
        aggregate: Aggregate::CountAndSum,
        acl,
        // No filter, predicate, object bound, sort, or cursor: count and sum
        // only, as on the v0.1 contract.
        ..EvaluateRequest::default()
    })
}

pub fn sql_compare_signature(
    paths: &[Vec<&ObjectTypeIndexMember>],
    aggregation: &ObjectSetAggregation,
) -> Result<(usize, i64), ObjectLogCompareError> {
    if !aggregation.group_by.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "group_by buckets are not expressible on the tagged object-log evaluate API",
        ));
    }
    let mut roots = HashSet::new();
    let mut sum = 0i64;
    let summing = aggregation.function.eq_ignore_ascii_case("sum");
    for path in paths {
        if let Some(root) = path.first() {
            roots.insert(root.source_key.as_str());
        }
        if summing {
            if aggregation.property.is_empty() {
                return Err(ObjectLogCompareError::Unsupported(
                    "sum compare requires aggregation.property",
                ));
            }
            let leaf = path.last().ok_or(ObjectLogCompareError::Unsupported(
                "sum compare requires a leaf on every path",
            ))?;
            let raw = leaf.properties.get(&aggregation.property).ok_or(
                ObjectLogCompareError::Unsupported(
                    "sum property missing on a hop leaf; refusing vacuous compare",
                ),
            )?;
            let amount = raw.parse::<i64>().map_err(|_| {
                ObjectLogCompareError::Unsupported(
                    "sum property is not an i64; refusing vacuous compare",
                )
            })?;
            sum += amount;
        }
    }
    if paths.len() != roots.len() {
        return Err(ObjectLogCompareError::Unsupported(
            "path multiplicity is not expressible on the tagged object-log evaluate API",
        ));
    }
    Ok((roots.len(), sum))
}

/// One evaluated kind as the dual-read canary sees it: its active policy, the
/// properties its schema declares (`None` when the kind has no schema), and
/// the properties this evaluate reads on it (filters, grouping, sum, joins).
pub struct ObjectLogAclKind<'a> {
    pub kind: &'a str,
    pub policy: Option<&'a ObjectSecurityPolicy>,
    pub schema_properties: Option<Vec<String>>,
    pub read_properties: BTreeSet<String>,
}

/// Project clerk property grants into the tagged multi-deny ACL (#1112).
///
/// A kind with a grant allow-list denies every declared property that is
/// neither granted nor read by this evaluate, so the canary witnesses the
/// narrowed view instead of a false allow-all. When the evaluate reads an
/// ungranted property (a join), or a narrowed kind has no schema to bound the
/// deny list, the SQL answer is wider than the ACL: the canary is skipped
/// rather than compared against a pretended view.
pub fn project_object_log_acl<'a>(
    kinds: impl IntoIterator<Item = ObjectLogAclKind<'a>>,
) -> Result<PropertyAcl, ObjectLogCompareError> {
    let mut acl = PropertyAcl::allow_all();
    let mut denied = BTreeSet::new();
    for kind in kinds {
        let Some(grants) = kind
            .policy
            .and_then(|policy| policy.property_grants.as_ref())
            .filter(|grants| !grants.is_empty())
        else {
            continue;
        };
        let granted = grants
            .iter()
            .map(|grant| grant.property.as_str())
            .collect::<BTreeSet<_>>();
        if kind
            .read_properties
            .iter()
            .any(|property| !granted.contains(property.as_str()))
        {
            return Err(ObjectLogCompareError::GrantNarrowed);
        }
        let Some(declared) = kind.schema_properties else {
            return Err(ObjectLogCompareError::GrantNarrowed);
        };
        for property in declared {
            if !granted.contains(property.as_str())
                && denied.insert((kind.kind.to_string(), property.clone()))
            {
                acl.insert_deny(kind.kind, &property)
                    .map_err(|_| ObjectLogCompareError::GrantNarrowed)?;
            }
        }
    }
    Ok(acl)
}

pub fn compare_sql_to_log(
    config: &ObjectLogDualRead,
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    sql_paths: &[Vec<&ObjectTypeIndexMember>],
    acl: PropertyAcl,
    max_rows_scanned: i32,
) -> Result<(), ObjectLogCompareError> {
    if !config.enabled {
        return Err(ObjectLogCompareError::Disabled);
    }
    if max_rows_scanned <= 0 {
        return Err(ObjectLogCompareError::Unbounded);
    }
    if !config.take_sample() {
        return Ok(());
    }
    let path = config
        .log_path
        .as_deref()
        .ok_or(ObjectLogCompareError::MissingLog)?;
    compare_sql_to_log_path(path, descriptor, hops, aggregation, sql_paths, acl)
}

pub fn compare_sql_to_log_path(
    path: &Path,
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    sql_paths: &[Vec<&ObjectTypeIndexMember>],
    acl: PropertyAcl,
) -> Result<(), ObjectLogCompareError> {
    let cache = OBJECT_LOG_STORE.get_or_init(|| Mutex::new(None));
    compare_sql_to_log_with_cache(cache, path, descriptor, hops, aggregation, sql_paths, acl)
}

fn compare_sql_to_log_with_cache(
    cache: &Mutex<Option<CachedObjectLogStore>>,
    path: &Path,
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    sql_paths: &[Vec<&ObjectTypeIndexMember>],
    acl: PropertyAcl,
) -> Result<(), ObjectLogCompareError> {
    if !path.exists() {
        return Err(ObjectLogCompareError::MissingLog);
    }
    let request = map_evaluate_request(descriptor, hops, aggregation, acl)?;
    let log = with_object_log_store_cache(cache, path, |store| {
        ObjectSet::new(LocalCompute)
            .evaluate(store, &request)
            .map_err(|error| format!("{error:?}"))
    })
    .map_err(ObjectLogCompareError::Evaluate)?;
    let (sql_roots, sql_sum) = sql_compare_signature(sql_paths, aggregation)?;
    let sum_matches = request.sum_property.is_empty() || sql_sum == log.sum_amount;
    if sql_roots == log.two_hop_count && sum_matches {
        return Ok(());
    }
    Err(ObjectLogCompareError::Mismatch {
        sql_roots,
        sql_sum,
        log,
    })
}

/// Append an admitted object through tagged mikura ingest when the log lacks
/// this identity at the current property map. A receipted retry of the same
/// mutation does not bump generation. An update whose properties differ from
/// the stored record is appended.
///
/// Clerk admission and receipts stay here. The log owns identity generations.
/// Missing `SEKAI_OBJECT_LOG` skips ingest so SQL-only fixtures keep working.
/// A configured object-log host (`SEKAI_OBJECT_LOG_HOST`, ADR 0088) owns the
/// log instead: admits go through it, and it is exclusive with a local log.
pub fn ensure_admitted_object_in_configured_log(object: &Object) -> Result<Option<u64>, String> {
    let host = configured_log_host()?;
    let path = configured_log_path();
    let path = match (host, path) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "{LOG_PATH_ENV} and {} are mutually exclusive",
                crate::sekai::object_log_host::HOST_ENV
            ));
        }
        (Some(host), None) => return host.admit(object_record(object)).map(Some),
        (None, None) => return Ok(None),
        (None, Some(path)) => path,
    };
    #[cfg(test)]
    if FAIL_NEXT_INGEST.with(|flag| flag.replace(false)) {
        return Err("injected object-log ingest failure".into());
    }
    if path.exists() {
        // #1106: an open/read failure here falls through to apply, exactly
        // as the pre-cache `if let Ok(store) = Store::open(&path)` guard
        // did — an unreadable log is "couldn't verify the check", not a
        // reason to fail the admission.
        // #1127: a direct identity lookup replaces the full-kind scan.
        let existing = with_cached_object_log_store(&path, |store| {
            Ok(visible_record(store, &object.kind, &object.id)
                .filter(|record| record.props == object.properties)
                .map(|record| record.r#gen))
        });
        if let Ok(Some(generation)) = existing {
            return Ok(Some(generation));
        }
    }
    apply_admitted_object_to_log(&path, object).map(Some)
}

fn configured_log_host() -> Result<Option<crate::sekai::object_log_host::ObjectLogHost>, String> {
    #[cfg(test)]
    {
        let override_host = TEST_LOG_HOST.with(|slot| slot.borrow().clone());
        if override_host.is_some() {
            return Ok(override_host);
        }
    }
    crate::sekai::object_log_host::ObjectLogHost::from_env()
}

#[cfg(test)]
pub fn with_test_log_host<R>(
    host: crate::sekai::object_log_host::ObjectLogHost,
    body: impl FnOnce() -> R,
) -> R {
    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            TEST_LOG_HOST.with(|slot| {
                *slot.borrow_mut() = None;
            });
        }
    }
    TEST_LOG_HOST.with(|slot| {
        *slot.borrow_mut() = Some(host);
    });
    let _clear = ClearOnDrop;
    body()
}

fn configured_log_path() -> Option<PathBuf> {
    #[cfg(test)]
    {
        let override_path = TEST_LOG_PATH.with(|slot| slot.borrow().clone());
        if override_path.is_some() {
            return override_path;
        }
    }
    env::var(LOG_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
pub fn with_test_log_path<R>(path: &Path, body: impl FnOnce() -> R) -> R {
    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            TEST_LOG_PATH.with(|slot| {
                *slot.borrow_mut() = None;
            });
        }
    }
    TEST_LOG_PATH.with(|slot| {
        *slot.borrow_mut() = Some(path.to_path_buf());
    });
    let _clear = ClearOnDrop;
    body()
}

/// One admit waiting for its record's commit (#1127).
struct IngestTicket {
    object: Object,
    outcome: Mutex<Option<Result<u64, String>>>,
}

impl IngestTicket {
    fn finish(&self, outcome: Result<u64, String>) {
        *self
            .outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(outcome);
    }

    fn take(&self) -> Option<Result<u64, String>> {
        self.outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

/// Queued admits per log path, so admits to unrelated logs never scan or
/// commit each other's records.
type IngestQueue = Mutex<std::collections::HashMap<PathBuf, Vec<std::sync::Arc<IngestTicket>>>>;

static INGEST_QUEUE: OnceLock<IngestQueue> = OnceLock::new();

fn ingest_queue() -> &'static IngestQueue {
    INGEST_QUEUE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum InjectedBatchFailure {
    RolledBack,
    CommittedThenFailed,
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_BATCH: std::cell::Cell<Option<InjectedBatchFailure>> =
        const { std::cell::Cell::new(None) };
}

fn run_batch(store: &mut Store, records: Vec<ObjectRecord>) -> Result<(), String> {
    #[cfg(test)]
    match FAIL_NEXT_BATCH.with(|flag| flag.take()) {
        Some(InjectedBatchFailure::RolledBack) => {
            return Err("injected batch failure before the log commit".into());
        }
        Some(InjectedBatchFailure::CommittedThenFailed) => {
            mikura_ingest::BatchIngest::run(store, records)?;
            return Err("injected batch failure after the log commit".into());
        }
        None => {}
    }
    mikura_ingest::BatchIngest::run(store, records)
}

/// Appends one admitted object and returns its identity generation.
///
/// Group commit (#1127): concurrent admits enqueue their records, and the
/// caller that holds the object-log handle commits every queued record for
/// that log as one mikura batch, so they share one fsync. Each admit returns
/// only after the commit that covers its record, so a returned admit is as
/// durable as a single-record ingest.
pub fn apply_admitted_object_to_log(path: &Path, object: &Object) -> Result<u64, String> {
    let cache = OBJECT_LOG_STORE.get_or_init(|| Mutex::new(None));
    apply_through_queue(cache, ingest_queue(), path, object)
}

/// A leader finishes every ticket it drains before it releases the handle
/// lock, so once this caller holds the lock its ticket is either finished or
/// still queued. A ticket stays queued after a successful pass only while an
/// older record for the same identity was ahead of it.
fn apply_through_queue(
    cache: &Mutex<Option<CachedObjectLogStore>>,
    queue: &IngestQueue,
    path: &Path,
    object: &Object,
) -> Result<u64, String> {
    let ticket = std::sync::Arc::new(IngestTicket {
        object: object.clone(),
        outcome: Mutex::new(None),
    });
    queue
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(path.to_path_buf())
        .or_default()
        .push(ticket.clone());
    let error = loop {
        let mut opened = false;
        let led = with_object_log_store_cache(cache, path, |store| {
            opened = true;
            commit_queued(store, queue, path)
        });
        if let Some(outcome) = ticket.take() {
            return outcome;
        }
        match led {
            // An older record for the same identity went first; every pass
            // commits the oldest queued record per identity, so lead again.
            Ok(()) => continue,
            // A leader finishes every record it drains, so this one was never
            // attempted: another record's batch failed. That pass still
            // finished the records it drained, so the queue ahead of this one
            // shrank; lead again on a fresh handle.
            Err(_) if opened => continue,
            Err(error) => break error,
        }
    };
    // The handle failed before this record was drained. Withdraw it so a
    // later leader cannot ingest a record whose admit already saw the failure.
    let withdrawn = {
        let mut queued = queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match queued.get_mut(path) {
            Some(pending) => {
                let before = pending.len();
                pending.retain(|entry| !std::sync::Arc::ptr_eq(entry, &ticket));
                let withdrawn = pending.len() != before;
                if pending.is_empty() {
                    queued.remove(path);
                }
                withdrawn
            }
            None => false,
        }
    };
    if withdrawn {
        return Err(error);
    }
    // Another leader took it after this caller released the lock; that
    // leader finishes it before releasing the lock this call now waits on.
    let _ = with_object_log_store_cache(cache, path, |_| Ok(()));
    ticket.take().unwrap_or(Err(error))
}

/// Drains the queued records for `path` and commits them together. A
/// second record for an identity already in this batch waits for the next
/// batch, so every admit keeps its own generation.
fn commit_queued(store: &mut Store, queue: &IngestQueue, path: &Path) -> Result<(), String> {
    let batch = {
        let mut queued = queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(pending) = queued.get_mut(path) else {
            return Ok(());
        };
        let mut seen = HashSet::new();
        let mut batch = Vec::new();
        pending.retain(|ticket| {
            if !seen.insert((ticket.object.kind.clone(), ticket.object.id.clone())) {
                return true;
            }
            batch.push(ticket.clone());
            false
        });
        if pending.is_empty() {
            queued.remove(path);
        }
        batch
    };
    if batch.is_empty() {
        return Ok(());
    }
    let generation = |store: &Store, ticket: &IngestTicket| {
        identity_generation(store, &ticket.object.kind, &ticket.object.id)
    };
    let pages_before = store.committed_pages();
    let records = batch
        .iter()
        .map(|ticket| object_record(&ticket.object))
        .collect::<Vec<_>>();
    let Err(error) = run_batch(store, records) else {
        for ticket in &batch {
            ticket.finish(generation(store, ticket));
        }
        return Ok(());
    };
    // The batch either rolled back as a unit or committed to the log and then
    // failed afterwards. The log itself says which: reopen it from disk and
    // compare its committed page count, which a batch commit advances and a
    // rollback does not. The pinned mikura `Store::append_batch` holds page
    // commits for the whole batch and publishes it with one superblock flush,
    // so a batch is never partly committed. This reads neither the error text nor per-record
    // state, so an idempotent re-admit is judged like any other record.
    let reopened = match Store::open(path) {
        Ok(reopened) => reopened,
        Err(reopen) => {
            for ticket in &batch {
                ticket.finish(Err(format!("{error}; reopening the log failed: {reopen}")));
            }
            return Err(error);
        }
    };
    let committed = reopened.committed_pages() > pages_before;
    *store = reopened;
    for (index, ticket) in batch.iter().enumerate() {
        if committed {
            ticket.finish(generation(store, ticket));
            continue;
        }
        // A rolled-back batch retries each record alone, so one bad record
        // cannot fail the rest. A failed retry reopens the handle before the
        // next record, since a failed write can leave it inconsistent.
        let outcome = mikura_ingest::BatchIngest::run(store, vec![object_record(&ticket.object)])
            .and_then(|()| generation(store, ticket));
        if outcome.is_err() {
            match Store::open(path) {
                Ok(reopened) => *store = reopened,
                Err(reopen) => {
                    ticket.finish(outcome);
                    for rest in &batch[index + 1..] {
                        rest.finish(Err(format!("{error}; reopening the log failed: {reopen}")));
                    }
                    return Err(error);
                }
            }
        }
        ticket.finish(outcome);
    }
    // Drop the handle after any failed batch, as a single-record failure
    // always has.
    Err(error)
}

fn object_record(object: &Object) -> ObjectRecord {
    ObjectRecord {
        r#gen: 0,
        kind: object.kind.clone(),
        key: object.id.clone(),
        hidden: false,
        // Admission ingest carries no mikura Action id; ingest idempotency
        // stays the receipted clerk admission.
        action_id: None,
        props: object.properties.clone(),
    }
}

pub fn identity_generation(store: &Store, kind: &str, key: &str) -> Result<u64, String> {
    visible_record(store, kind, key)
        .map(|record| record.r#gen)
        .ok_or_else(|| format!("mikura identity missing for {kind}:{key}"))
}

/// The current visible record for one identity, by direct lookup. Missing or
/// hidden identities read as absent, as the v0.1 visible-kind scan did.
fn visible_record(store: &Store, kind: &str, key: &str) -> Option<ObjectRecord> {
    store
        .load(kind, key, &PropertyAcl::allow_all())
        .ok()
        .filter(|record| !record.hidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_host_keeps_the_canary_off_the_local_log() {
        let local = ObjectLogDualRead::resolve(
            Some("1".into()),
            None,
            Some("./objects.mikura".into()),
            None,
        );
        assert_eq!(local.log_path, Some(PathBuf::from("./objects.mikura")));
        let hosted = ObjectLogDualRead::resolve(
            Some("1".into()),
            None,
            Some("./objects.mikura".into()),
            Some("127.0.0.1:7070".into()),
        );
        assert!(hosted.enabled);
        assert_eq!(hosted.log_path, None, "#1202: no local Store behind a host");
        let blank_host = ObjectLogDualRead::resolve(
            Some("1".into()),
            None,
            Some("./objects.mikura".into()),
            Some("  ".into()),
        );
        assert_eq!(blank_host.log_path, Some(PathBuf::from("./objects.mikura")));
    }
    use mikura::ObjectRecord;
    use mikura_ingest::BatchIngest;
    use std::collections::{BTreeMap, HashMap};

    fn member(kind: &str, key: &str, property: &str, value: &str) -> ObjectTypeIndexMember {
        ObjectTypeIndexMember {
            kind: kind.into(),
            source_key: key.into(),
            object_id: format!("{kind}:{key}"),
            properties: BTreeMap::from([(property.into(), value.into())]),
            ..ObjectTypeIndexMember::default()
        }
    }

    #[test]
    fn admitted_ingest_advances_identity_generation() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let object = crate::domain::Object {
            id: "c1".into(),
            kind: "Customer".into(),
            name: "Acme".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: HashMap::from([("region".into(), "eu".into())]),
            created: 1,
            updated: 1,
        };
        assert_eq!(apply_admitted_object_to_log(&log, &object).unwrap(), 1);
        assert_eq!(apply_admitted_object_to_log(&log, &object).unwrap(), 2);
        let store = Store::open(&log).unwrap();
        assert_eq!(identity_generation(&store, "Customer", "c1").unwrap(), 2);
    }

    #[test]
    fn object_log_store_cache_reuses_evicts_on_path_change_and_evicts_on_error() {
        // #1106: exercises `with_object_log_store_cache` directly against a
        // cache instance this test owns, not the process-wide
        // `OBJECT_LOG_STORE` static. That static is shared with every other
        // test in this binary; asserting exact open counts against it would
        // be a real race under the default parallel test runner (an
        // unrelated concurrently-running test using a different path would
        // evict this test's cached handle between iterations). An owned
        // cache instance makes the count deterministic while still proving
        // the real, shared code path's behavior.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let other_log = dir.path().join("other.mikura");
        let object = crate::domain::Object {
            id: "c1".into(),
            kind: "Customer".into(),
            name: "Acme".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: HashMap::from([("region".into(), "eu".into())]),
            created: 1,
            updated: 1,
        };
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        let ingest_and_read = |cache: &Mutex<Option<CachedObjectLogStore>>, path: &Path| {
            with_object_log_store_cache(cache, path, |store| {
                BatchIngest::run(store, vec![object_record(&object)])?;
                identity_generation(store, &object.kind, &object.id)
            })
        };

        OBJECT_LOG_STORE_OPENS.with(|opens| opens.set(0));
        for generation in 1..=5u64 {
            assert_eq!(ingest_and_read(&cache, &log).unwrap(), generation);
        }
        // `Store::open`/`Store::create` reads and replays the whole on-disk
        // log into memory; five admits to the same path pay that cost once.
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 1);

        // A different path is a genuinely different log: it must still
        // open fresh rather than silently reuse the first path's handle.
        assert_eq!(ingest_and_read(&cache, &other_log).unwrap(), 1);
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 2);

        // Switching back to the first path also reopens (its in-memory
        // state was evicted by the switch above) rather than serving the
        // second path's now-cached handle.
        assert_eq!(ingest_and_read(&cache, &log).unwrap(), 6);
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 3);

        // A failed operation must evict the cache rather than leave a
        // handle with possibly-inconsistent writer state cached for the
        // next call to keep writing through.
        let failing = with_object_log_store_cache(&cache, &log, |_store| {
            Err::<(), _>("injected failure".to_string())
        });
        assert!(failing.is_err());
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 3);
        assert_eq!(ingest_and_read(&cache, &log).unwrap(), 7);
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 4);
    }

    #[test]
    fn log_stamp_detects_a_superblock_rewrite_at_the_same_length_and_mtime() {
        // A commit that reuses a torn tail page's length inside one coarse
        // modification-time tick still rewrites the superblock.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        std::fs::write(&log, vec![1u8; 2 * SUPERBLOCK_BYTES]).unwrap();
        let before = log_stamp(&log).unwrap();
        let mut rewritten = vec![1u8; 2 * SUPERBLOCK_BYTES];
        rewritten[8] = 2;
        std::fs::write(&log, rewritten).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&log)
            .unwrap()
            .set_modified(before.1.unwrap())
            .unwrap();
        let after = log_stamp(&log).unwrap();
        assert_eq!((after.0, after.1), (before.0, before.1));
        assert_ne!(after, before);
    }

    #[test]
    fn every_mikura_commit_rewrites_the_superblock_the_stamp_digests() {
        // Contract with the pinned mikura tag: a dependency bump that moves
        // the superblock or stops rewriting it on commit fails here.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut store = Store::create(&log).unwrap();
        let mut previous = log_stamp(&log).unwrap().2;
        for generation in 1..=3u64 {
            BatchIngest::run(
                &mut store,
                vec![ObjectRecord {
                    action_id: None,
                    r#gen: generation,
                    kind: "Customer".into(),
                    key: "c1".into(),
                    hidden: false,
                    props: HashMap::from([("n".into(), generation.to_string())]),
                }],
            )
            .unwrap();
            let digest = log_stamp(&log).unwrap().2;
            assert_ne!(
                digest, previous,
                "commit {generation} left the superblock unchanged"
            );
            previous = digest;
        }
    }

    #[test]
    fn ensure_skips_matching_identity_and_appends_property_change() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut object = crate::domain::Object {
            id: "c1".into(),
            kind: "Customer".into(),
            name: "Acme".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: HashMap::from([("region".into(), "eu".into())]),
            created: 1,
            updated: 1,
        };
        with_test_log_path(&log, || {
            assert_eq!(
                ensure_admitted_object_in_configured_log(&object).unwrap(),
                Some(1)
            );
            assert_eq!(
                ensure_admitted_object_in_configured_log(&object).unwrap(),
                Some(1)
            );
            object.properties.insert("region".into(), "us".into());
            assert_eq!(
                ensure_admitted_object_in_configured_log(&object).unwrap(),
                Some(2)
            );
        });
    }

    #[test]
    fn queued_admits_share_one_commit_and_keep_their_generations() {
        // #1127: records queued while another admit holds the handle commit
        // together, as one log page, and each gets its own generation.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group.mikura");
        let object = |id: &str| Object {
            id: id.into(),
            kind: "Customer".into(),
            name: id.into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([("region".into(), id.into())]),
            created: 1,
            updated: 1,
        };
        // An owned queue and handle keep this test independent of the
        // process-wide ones other tests share.
        let queue: IngestQueue = Mutex::new(std::collections::HashMap::new());
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        apply_through_queue(&cache, &queue, &path, &object("seed")).unwrap();
        let pages_before = Store::open(&path).unwrap().committed_pages();
        let queued = ["q1", "q2", "q3", "q4"]
            .into_iter()
            .map(|id| {
                let ticket = std::sync::Arc::new(IngestTicket {
                    object: object(id),
                    outcome: Mutex::new(None),
                });
                queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .entry(path.clone())
                    .or_default()
                    .push(ticket.clone());
                ticket
            })
            .collect::<Vec<_>>();
        let leader = apply_through_queue(&cache, &queue, &path, &object("leader")).unwrap();
        let mut generations = queued
            .iter()
            .map(|ticket| ticket.take().expect("drained by the leader").unwrap())
            .collect::<Vec<_>>();
        generations.push(leader);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.committed_pages(), pages_before + 1);
        for (id, generation) in ["q1", "q2", "q3", "q4", "leader"].iter().zip(&generations) {
            assert_eq!(
                identity_generation(&store, "Customer", id).unwrap(),
                *generation
            );
        }
    }

    fn queue_admits_and_fail_their_batch(
        failure: InjectedBatchFailure,
    ) -> (Vec<u64>, u32, u32, std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("failed-batch.mikura");
        let object = |id: &str, region: &str| Object {
            id: id.into(),
            kind: "Customer".into(),
            name: id.into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([("region".into(), region.into())]),
            created: 1,
            updated: 1,
        };
        let queue: IngestQueue = Mutex::new(std::collections::HashMap::new());
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        apply_through_queue(&cache, &queue, &path, &object("same", "eu")).unwrap();
        let pages_before = Store::open(&path).unwrap().committed_pages();
        // An identical re-admit rides in the batch with two new records.
        let queued = [object("same", "eu"), object("new-1", "us")]
            .into_iter()
            .map(|object| {
                let ticket = std::sync::Arc::new(IngestTicket {
                    object,
                    outcome: Mutex::new(None),
                });
                queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .entry(path.clone())
                    .or_default()
                    .push(ticket.clone());
                ticket
            })
            .collect::<Vec<_>>();
        FAIL_NEXT_BATCH.with(|flag| flag.set(Some(failure)));
        let leader = apply_through_queue(&cache, &queue, &path, &object("new-2", "ap"));
        assert!(
            leader.is_ok(),
            "the leader's record is resolved: {leader:?}"
        );
        let mut generations = queued
            .iter()
            .map(|ticket| ticket.take().expect("drained by the leader").unwrap())
            .collect::<Vec<_>>();
        generations.push(leader.unwrap());
        let pages_after = Store::open(&path).unwrap().committed_pages();
        (generations, pages_before, pages_after, path, dir)
    }

    #[test]
    fn a_batch_that_committed_before_failing_is_not_appended_again() {
        let (generations, pages_before, pages_after, path, _dir) =
            queue_admits_and_fail_their_batch(InjectedBatchFailure::CommittedThenFailed);
        assert_eq!(pages_after, pages_before + 1, "no record is appended twice");
        let store = Store::open(&path).unwrap();
        for (id, generation) in ["same", "new-1", "new-2"].iter().zip(&generations) {
            assert_eq!(
                identity_generation(&store, "Customer", id).unwrap(),
                *generation
            );
        }
    }

    #[test]
    fn a_rolled_back_batch_retries_each_record_alone() {
        let (generations, pages_before, pages_after, path, _dir) =
            queue_admits_and_fail_their_batch(InjectedBatchFailure::RolledBack);
        assert_eq!(pages_after, pages_before + 3, "each record commits alone");
        let store = Store::open(&path).unwrap();
        for (id, generation) in ["same", "new-1", "new-2"].iter().zip(&generations) {
            assert_eq!(
                identity_generation(&store, "Customer", id).unwrap(),
                *generation
            );
        }
    }

    #[test]
    fn an_admit_behind_a_failed_same_identity_batch_still_commits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("twin.mikura");
        let object = |region: &str| Object {
            id: "twin".into(),
            kind: "Customer".into(),
            name: "twin".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([("region".into(), region.into())]),
            created: 1,
            updated: 1,
        };
        let queue: IngestQueue = Mutex::new(std::collections::HashMap::new());
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        let older = std::sync::Arc::new(IngestTicket {
            object: object("eu"),
            outcome: Mutex::new(None),
        });
        queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(path.clone())
            .or_default()
            .push(older.clone());
        // The older record's batch fails; this admit was never in it.
        FAIL_NEXT_BATCH.with(|flag| flag.set(Some(InjectedBatchFailure::RolledBack)));
        let newer = apply_through_queue(&cache, &queue, &path, &object("us")).unwrap();
        let older = older.take().expect("drained first").unwrap();
        assert!(newer > older, "the newer admit commits after its twin");
        let store = Store::open(&path).unwrap();
        assert_eq!(
            identity_generation(&store, "Customer", "twin").unwrap(),
            newer
        );
    }

    #[test]
    fn concurrent_admits_for_one_identity_all_commit_in_turn() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("same-identity.mikura"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(6));
        let handles = (0..6)
            .map(|worker| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..5)
                        .map(|index| {
                            let object = Object {
                                id: "shared".into(),
                                kind: "Customer".into(),
                                name: "shared".into(),
                                namespace: "sales".into(),
                                external_id: String::new(),
                                properties: std::collections::HashMap::from([(
                                    "region".into(),
                                    format!("r-{worker}-{index}"),
                                )]),
                                created: 1,
                                updated: 1,
                            };
                            apply_admitted_object_to_log(&path, &object).unwrap()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut generations = handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        generations.sort_unstable();
        generations.dedup();
        assert_eq!(
            generations.len(),
            30,
            "every admit keeps its own generation"
        );
    }

    #[test]
    fn concurrent_admits_all_commit_with_matching_generations() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("concurrent.mikura"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles = (0..8)
            .map(|worker| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..10)
                        .map(|index| {
                            let id = format!("c-{worker}-{index}");
                            let object = Object {
                                id: id.clone(),
                                kind: "Customer".into(),
                                name: id.clone(),
                                namespace: "sales".into(),
                                external_id: String::new(),
                                properties: std::collections::HashMap::from([(
                                    "region".into(),
                                    "eu".into(),
                                )]),
                                created: 1,
                                updated: 1,
                            };
                            (id, apply_admitted_object_to_log(&path, &object).unwrap())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        let store = Store::open(&path).unwrap();
        assert_eq!(results.len(), 80);
        for (id, generation) in &results {
            assert_eq!(
                identity_generation(&store, "Customer", id).unwrap(),
                *generation
            );
        }
        assert!(store.committed_pages() <= 80);
    }

    #[test]
    fn dual_read_matches_and_fails_closed_on_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut store = Store::create(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    kind: "Customer".into(),
                    key: "c1".into(),
                    hidden: false,
                    props: HashMap::from([("region".into(), "eu".into())]),
                },
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    kind: "Order".into(),
                    key: "o1".into(),
                    hidden: false,
                    props: HashMap::from([("customer_id".into(), "c1".into())]),
                },
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    kind: "Shipment".into(),
                    key: "s1".into(),
                    hidden: false,
                    props: HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "10".into()),
                    ]),
                },
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    kind: "Shipment".into(),
                    key: "s-hidden".into(),
                    hidden: true,
                    props: HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "99".into()),
                    ]),
                },
            ],
        )
        .unwrap();
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        };
        let hops = vec![
            crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                ..Default::default()
            },
            crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Shipment".into(),
                join_property: "order_id".into(),
                ..Default::default()
            },
        ];
        let aggregation = ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: String::new(),
        };
        let customer = member("Customer", "c1", "region", "eu");
        let order = member("Order", "o1", "customer_id", "c1");
        let shipment = member("Shipment", "s1", "amount", "10");
        let paths = vec![vec![&customer, &order, &shipment]];
        // #1110: an owned cache (not the shared static) keeps open counts
        // deterministic under the parallel test runner.
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        let compare = || {
            compare_sql_to_log_with_cache(
                &cache,
                &log,
                &descriptor,
                &hops,
                &aggregation,
                &paths,
                PropertyAcl::allow_all(),
            )
        };
        OBJECT_LOG_STORE_OPENS.with(|opens| opens.set(0));
        for _ in 0..4 {
            compare().unwrap();
        }
        // Canary samples share one handle instead of a Store::open each.
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 1);

        BatchIngest::run(
            &mut store,
            vec![ObjectRecord {
                action_id: None,
                r#gen: 1,
                kind: "Shipment".into(),
                key: "s2".into(),
                hidden: false,
                props: HashMap::from([
                    ("order_id".into(), "o1".into()),
                    ("amount".into(), "5".into()),
                ]),
            }],
        )
        .unwrap();
        // A write that bypassed the cached handle changes the file, so the
        // next sample reopens and sees it rather than serving stale memory.
        let err = compare().unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::Mismatch { .. }));
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 2);
        assert!(compare().is_err());
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 2);
    }

    #[test]
    fn filters_fail_closed_instead_of_dropping() {
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            property_filters: vec![crate::domain::PropertyFilter {
                key: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            }],
            ..ObjectSetDescriptor::default()
        };
        let err = map_evaluate_request(
            &descriptor,
            &[crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                ..Default::default()
            }],
            &ObjectSetAggregation {
                function: "count".into(),
                ..Default::default()
            },
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::Unsupported(_)));
    }

    #[test]
    fn incoming_hop_fails_closed_instead_of_outbound() {
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        };
        let err = map_evaluate_request(
            &descriptor,
            &[crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                direction: "incoming".into(),
                ..Default::default()
            }],
            &ObjectSetAggregation {
                function: "count".into(),
                ..Default::default()
            },
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("direction"))
        );

        map_evaluate_request(
            &descriptor,
            &[crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                direction: "outgoing".into(),
                ..Default::default()
            }],
            &ObjectSetAggregation {
                function: "count".into(),
                ..Default::default()
            },
            PropertyAcl::allow_all(),
        )
        .unwrap();
    }

    #[test]
    fn group_by_path_multiplicity_and_non_i64_sum_fail_closed() {
        let aggregation = ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: "region".into(),
        };
        let customer = member("Customer", "c1", "region", "eu");
        let order = member("Order", "o1", "customer_id", "c1");
        let shipment = member("Shipment", "s1", "amount", "10");
        let err =
            sql_compare_signature(&[vec![&customer, &order, &shipment]], &aggregation).unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("group_by"))
        );

        let no_group = ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: String::new(),
        };
        let extra = member("Shipment", "s2", "amount", "5");
        let err = sql_compare_signature(
            &[
                vec![&customer, &order, &shipment],
                vec![&customer, &order, &extra],
            ],
            &no_group,
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("multiplicity"))
        );

        let bad = member("Shipment", "s1", "amount", "10.5");
        let err = sql_compare_signature(&[vec![&customer, &order, &bad]], &no_group).unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("i64"))
        );
    }

    #[test]
    fn dual_read_refuses_unbounded_and_skips_unsampled_without_opening() {
        SAMPLE_TICK.store(0, Ordering::Relaxed);
        let config = ObjectLogDualRead {
            enabled: true,
            log_path: None,
            sample_n: 2,
        };
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        };
        let hops = [crate::sekai::object_set::ObjectSetTraversal {
            far_kind: "Order".into(),
            join_property: "customer_id".into(),
            ..Default::default()
        }];
        let aggregation = ObjectSetAggregation {
            function: "count".into(),
            ..Default::default()
        };
        let err = compare_sql_to_log(
            &config,
            &descriptor,
            &hops,
            &aggregation,
            &[],
            PropertyAcl::allow_all(),
            0,
        )
        .unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::Unbounded));

        SAMPLE_TICK.store(1, Ordering::Relaxed);
        compare_sql_to_log(
            &config,
            &descriptor,
            &hops,
            &aggregation,
            &[],
            PropertyAcl::allow_all(),
            10,
        )
        .unwrap();
    }

    fn canary_descriptor() -> ObjectSetDescriptor {
        ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        }
    }

    fn canary_hops() -> [crate::sekai::object_set::ObjectSetTraversal; 1] {
        [crate::sekai::object_set::ObjectSetTraversal {
            far_kind: "Order".into(),
            join_property: "customer_id".into(),
            ..Default::default()
        }]
    }

    fn canary_count() -> ObjectSetAggregation {
        ObjectSetAggregation {
            function: "count".into(),
            ..Default::default()
        }
    }

    #[test]
    fn unsampled_canary_does_not_load_active_object_policy() {
        SAMPLE_TICK.store(1, Ordering::Relaxed);
        let config = ObjectLogDualRead {
            enabled: true,
            log_path: None,
            sample_n: 2,
        };
        let mut policy_loads = 0u32;
        if should_fetch_canary_policies(
            &config,
            &canary_descriptor(),
            &canary_hops(),
            &canary_count(),
            10,
        ) {
            policy_loads += 1;
        }
        assert_eq!(
            policy_loads, 0,
            "unsampled dual-read must not load active_object_policy"
        );
    }

    #[test]
    fn unexpressible_canary_skips_policy_after_sample() {
        SAMPLE_TICK.store(0, Ordering::Relaxed);
        let config = ObjectLogDualRead {
            enabled: true,
            log_path: None,
            sample_n: 1,
        };
        let mut descriptor = canary_descriptor();
        descriptor.property_filters = vec![crate::domain::PropertyFilter {
            key: "region".into(),
            op: "eq".into(),
            value: "eu".into(),
        }];
        let mut policy_loads = 0u32;
        if should_fetch_canary_policies(&config, &descriptor, &canary_hops(), &canary_count(), 10) {
            policy_loads += 1;
        }
        assert_eq!(
            policy_loads, 0,
            "unexpressible grammar must skip active_object_policy after the sample tick"
        );
    }

    #[test]
    fn sampled_expressible_canary_loads_policy() {
        SAMPLE_TICK.store(0, Ordering::Relaxed);
        let config = ObjectLogDualRead {
            enabled: true,
            log_path: None,
            sample_n: 1,
        };
        assert!(should_fetch_canary_policies(
            &config,
            &canary_descriptor(),
            &canary_hops(),
            &canary_count(),
            10,
        ));
    }

    fn granted_customer_policy(
        granted: &[&str],
    ) -> crate::sekai::object_security::ObjectSecurityPolicy {
        crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(
                granted
                    .iter()
                    .map(|property| crate::sekai::object_security::PropertyGrant {
                        property: (*property).into(),
                        access: crate::sekai::object_security::PropertyGrantAccess::Read,
                    })
                    .collect(),
            ),
            value_instance_grants: None,
            required_purpose: None,
        }
    }

    fn customer_kind<'a>(
        policy: Option<&'a crate::sekai::object_security::ObjectSecurityPolicy>,
        schema: Option<&[&str]>,
        read: &[&str],
    ) -> ObjectLogAclKind<'a> {
        ObjectLogAclKind {
            kind: "Customer",
            policy,
            schema_properties: schema.map(|properties| {
                properties
                    .iter()
                    .map(|property| (*property).into())
                    .collect()
            }),
            read_properties: read.iter().map(|property| (*property).into()).collect(),
        }
    }

    #[test]
    fn grant_allow_lists_project_into_a_multi_deny_view() {
        // #1112: a narrowed kind denies every declared property it neither
        // grants nor reads, so the canary sees the narrowed view.
        let policy = granted_customer_policy(&["region", "tier"]);
        let acl = project_object_log_acl([customer_kind(
            Some(&policy),
            Some(&["region", "tier", "secret", "email"]),
            &["region"],
        )])
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.log");
        let mut store = Store::create(&log).unwrap();
        mikura_ingest::BatchIngest::run(
            &mut store,
            vec![ObjectRecord {
                r#gen: 0,
                kind: "Customer".into(),
                key: "c1".into(),
                hidden: false,
                action_id: None,
                props: HashMap::from([
                    ("region".into(), "eu".into()),
                    ("tier".into(), "2".into()),
                    ("secret".into(), "s".into()),
                    ("email".into(), "e".into()),
                ]),
            }],
        )
        .unwrap();
        let visible = store.load("Customer", "c1", &acl).unwrap();
        let mut keys = visible.props.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, ["region", "tier"]);
    }

    #[test]
    fn a_grant_narrowed_canary_compares_and_still_fails_closed() {
        // #1112: with Customer narrowed to `region`, the projected view hides
        // `secret`, the count and sum still match SQL, and a diverging log
        // still fails the canary instead of being skipped.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut store = Store::create(&log).unwrap();
        let record = |kind: &str, key: &str, props: &[(&str, &str)]| ObjectRecord {
            action_id: None,
            r#gen: 1,
            kind: kind.into(),
            key: key.into(),
            hidden: false,
            props: props
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),
        };
        BatchIngest::run(
            &mut store,
            vec![
                record("Customer", "c1", &[("region", "eu"), ("secret", "s")]),
                record("Order", "o1", &[("customer_id", "c1")]),
                record("Shipment", "s1", &[("order_id", "o1"), ("amount", "10")]),
            ],
        )
        .unwrap();
        let policy = granted_customer_policy(&["region"]);
        let acl = project_object_log_acl([
            customer_kind(Some(&policy), Some(&["region", "secret"]), &[]),
            ObjectLogAclKind {
                kind: "Order",
                policy: None,
                schema_properties: None,
                read_properties: BTreeSet::from(["customer_id".to_string()]),
            },
            ObjectLogAclKind {
                kind: "Shipment",
                policy: None,
                schema_properties: None,
                read_properties: BTreeSet::from(["order_id".to_string(), "amount".to_string()]),
            },
        ])
        .unwrap();
        assert!(
            !store
                .load("Customer", "c1", &acl)
                .unwrap()
                .props
                .contains_key("secret")
        );
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        };
        let hops = vec![
            crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                ..Default::default()
            },
            crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Shipment".into(),
                join_property: "order_id".into(),
                ..Default::default()
            },
        ];
        let aggregation = ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: String::new(),
        };
        let customer = member("Customer", "c1", "region", "eu");
        let order = member("Order", "o1", "customer_id", "c1");
        let shipment = member("Shipment", "s1", "amount", "10");
        let paths = vec![vec![&customer, &order, &shipment]];
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        let compare = || {
            compare_sql_to_log_with_cache(
                &cache,
                &log,
                &descriptor,
                &hops,
                &aggregation,
                &paths,
                acl.clone(),
            )
        };
        compare().unwrap();
        BatchIngest::run(
            &mut store,
            vec![record(
                "Shipment",
                "s2",
                &[("order_id", "o1"), ("amount", "5")],
            )],
        )
        .unwrap();
        assert!(matches!(
            compare().unwrap_err(),
            ObjectLogCompareError::Mismatch { .. }
        ));
    }

    #[test]
    fn a_wider_sql_read_or_unknown_schema_keeps_the_canary_skipped() {
        let policy = granted_customer_policy(&["region"]);
        // The evaluate joins on an ungranted property: SQL is wider than the ACL.
        assert!(matches!(
            project_object_log_acl([customer_kind(
                Some(&policy),
                Some(&["region", "account_id"]),
                &["account_id"],
            )]),
            Err(ObjectLogCompareError::GrantNarrowed)
        ));
        // No schema bounds the deny list.
        assert!(matches!(
            project_object_log_acl([customer_kind(Some(&policy), None, &["region"])]),
            Err(ObjectLogCompareError::GrantNarrowed)
        ));
        // No policy or no grants: the open view.
        assert_eq!(
            project_object_log_acl([customer_kind(None, None, &["anything"])]).unwrap(),
            PropertyAcl::allow_all()
        );
    }
}
