//! Fail-closed dual-read of EvaluateObjectSet against a tagged object-log library.
//!
//! `SEKAI_OBJECT_INDEX_DUAL_READ` compares SQL hop engines. This gate compares
//! the SQL projection to in-process mikura `ObjectSet::evaluate` (ADR 0081).
//! ADR 0091 / ADR 0112: the log owns identity generations keyed by
//! `(namespace, kind, key)`; EvaluateObjectSet keeps the SQL serving
//! projection.

use crate::domain::Object;
use crate::sekai::object_schema::{PropertyValue, property_values_equivalent};
use crate::sekai::object_security::ObjectSecurityPolicy;
use crate::sekai::object_set::{ObjectSetAggregation, ObjectSetDescriptor};
use crate::sekai::object_type_index::{
    ObjectTypeIndexEdit, ObjectTypeIndexMember, carry_index_edits, merge_index_edits,
    parse_property_edit_times,
};
use mikura::{
    Aggregate, Breakdown, EvaluateRequest, EvaluateResponse, Hop, LocalCompute, ObjectRecord,
    ObjectSet, OverlayPatch, PropertyAcl, Store, VersionOrigin,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub const DUAL_READ_ENV: &str = "SEKAI_OBJECT_LOG_DUAL_READ";
pub const LOG_PATH_ENV: &str = "SEKAI_OBJECT_LOG";
pub const SAMPLE_ENV: &str = "SEKAI_OBJECT_LOG_DUAL_READ_SAMPLE";
/// Default Combined/Sekai file name under `SEKAI_DATA_DIR`.
pub const DEFAULT_LOG_FILE: &str = "objects.mikura";
const DEFAULT_SAMPLE_N: u32 = 32;
const BACKFILL_MARKER_SUFFIX: &str = ".backfill-complete";

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
/// Combined/Sekai boot installs the resolved local path so later admits
/// use the same file the process opened.
static INSTALLED_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

struct CachedObjectLogStore {
    path: PathBuf,
    store: Option<Store>,
    stamp: Option<LogStamp>,
}

impl CachedObjectLogStore {
    fn store_mut(&mut self) -> Result<&mut Store, String> {
        self.store
            .as_mut()
            .ok_or_else(|| "object log handle dropped".into())
    }

    /// Drop the exclusive writer and open from disk again. mikura v0.5.0
    /// refuses a second `Store` on the same path (`LOG_IN_USE`).
    fn reopen(&mut self) -> Result<&mut Store, String> {
        self.store = None;
        let opened = Store::open(&self.path)?;
        self.stamp = log_stamp(&self.path);
        self.store = Some(opened);
        self.store_mut()
    }
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

fn open_or_create_store(path: &Path) -> Result<Store, String> {
    if path.exists() {
        Store::open(path)
    } else {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        Store::create(path)
    }
}

/// Runs `body` against a cached writer for `path`, reusing the handle when
/// it already wraps `path` and opening (creating the log and its parent
/// directory if `path` does not exist yet) otherwise. Holds the cache lock
/// for the whole check-then-use sequence so a concurrent caller can never
/// observe a handle for the wrong path. A failed `body` drops the writer
/// then immediately reopens so this process keeps the exclusive lock.
fn with_cached_object_log<R>(
    cache: &Mutex<Option<CachedObjectLogStore>>,
    path: &Path,
    body: impl FnOnce(&mut CachedObjectLogStore) -> Result<R, String>,
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
        // Drop the exclusive writer before opening again (mikura v0.5.0).
        *guard = None;
        #[cfg(test)]
        OBJECT_LOG_STORE_OPENS.with(|opens| opens.set(opens.get().saturating_add(1)));
        let store = open_or_create_store(path)?;
        *guard = Some(CachedObjectLogStore {
            path: path.to_path_buf(),
            store: Some(store),
            stamp: None,
        });
    }
    let cached = guard.as_mut().expect("cache populated above");
    let result = body(cached);
    if result.is_err() {
        // mikura's writer is not failure-atomic: drop it, then reopen so
        // this process keeps the exclusive lock. A reopen failure leaves
        // the cache empty and later admits fail closed.
        *guard = None;
        #[cfg(test)]
        OBJECT_LOG_STORE_OPENS.with(|opens| opens.set(opens.get().saturating_add(1)));
        if let Ok(store) = open_or_create_store(path) {
            *guard = Some(CachedObjectLogStore {
                path: path.to_path_buf(),
                store: Some(store),
                stamp: log_stamp(path),
            });
        }
    } else if let Some(cached) = guard.as_mut() {
        cached.stamp = log_stamp(path);
    }
    result
}

fn with_object_log_store_cache<R>(
    cache: &Mutex<Option<CachedObjectLogStore>>,
    path: &Path,
    body: impl FnOnce(&mut Store) -> Result<R, String>,
) -> Result<R, String> {
    with_cached_object_log(cache, path, |cached| body(cached.store_mut()?))
}

#[cfg(test)]
fn release_object_log_cache(cache: &Mutex<Option<CachedObjectLogStore>>) {
    *cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

#[cfg(test)]
pub(crate) fn release_process_object_log_cache() {
    if let Some(cache) = OBJECT_LOG_STORE.get() {
        release_object_log_cache(cache);
    }
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
        let host = env::var(crate::sekai::object_log_host::HOST_ENV).ok();
        let host_configured = host.as_ref().is_some_and(|value| !value.trim().is_empty());
        Self::resolve(
            env::var(DUAL_READ_ENV).ok(),
            env::var(SAMPLE_ENV).ok(),
            env::var(LOG_PATH_ENV).ok(),
            host,
        )
        .with_default_log(INSTALLED_LOG_PATH.get().cloned(), host_configured)
    }

    fn with_default_log(mut self, default: Option<PathBuf>, host_configured: bool) -> Self {
        if self.log_path.is_none() && !host_configured {
            self.log_path = default;
        }
        self
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

    pub fn take_sample(&self) -> bool {
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
    if !descriptor.order_by.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "SQL object-set order_by is one key; the object-log sorts up to three keys",
        ));
    }
    if !aggregation.group_by.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "SQL group_by falls back to the source key when the property is absent; the object-log uses an absent group",
        ));
    }
    let function = aggregation.function.to_ascii_lowercase();
    let uses_breakdown = matches!(function.as_str(), "min" | "max" | "avg" | "distinct");
    if function != "sum" && function != "count" && !uses_breakdown {
        return Err(ObjectLogCompareError::Unsupported(
            "object-log evaluate compares count, sum, min, max, avg, or distinct",
        ));
    }
    let sum_property = if aggregation.property.is_empty() {
        if function == "count" {
            String::new()
        } else if function == "sum" {
            return Err(ObjectLogCompareError::Unsupported(
                "sum compare requires aggregation.property",
            ));
        } else {
            return Err(ObjectLogCompareError::Unsupported(
                "min, max, avg, and distinct compare require aggregation.property",
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
    let breakdown = match function.as_str() {
        "distinct" => Some(Breakdown {
            group_by: Vec::new(),
            max_groups: 0,
            distinct: Some(sum_property.clone()),
        }),
        "min" | "max" | "avg" => Some(Breakdown {
            group_by: Vec::new(),
            max_groups: 0,
            distinct: None,
        }),
        _ => None,
    };
    Ok(EvaluateRequest {
        namespace: descriptor.namespace.clone(),
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
        breakdown,
        // No filter, predicate, object bound, sort, or cursor. Extra
        // aggregates use breakdown; count and sum keep the v0.1 shape.
        ..EvaluateRequest::default()
    })
}

#[derive(Debug)]
struct SqlLogSignature {
    roots: usize,
    sum: i64,
    n: u64,
    min: Option<i64>,
    max: Option<i64>,
}

/// i64 contribution table shared with mikura (ADR 0018). Values that parse as
/// `f64` but not `i64` would disagree with SQL object-set aggregation, so the
/// canary refuses rather than skipping them.
fn contributing_i64(raw: &str) -> Result<Option<i64>, ObjectLogCompareError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if let Ok(amount) = raw.parse::<i64>() {
        return Ok(Some(amount));
    }
    if raw.parse::<f64>().is_ok() {
        return Err(ObjectLogCompareError::Unsupported(
            "SQL aggregates parse f64; the object-log contributes i64 only",
        ));
    }
    Ok(None)
}

fn sql_compare_signature(
    paths: &[Vec<&ObjectTypeIndexMember>],
    aggregation: &ObjectSetAggregation,
) -> Result<SqlLogSignature, ObjectLogCompareError> {
    if !aggregation.group_by.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "SQL group_by falls back to the source key when the property is absent; the object-log uses an absent group",
        ));
    }
    let function = aggregation.function.to_ascii_lowercase();
    if function == "distinct" {
        return Err(ObjectLogCompareError::Unsupported(
            "SQL distinct counts numeric values; the object-log counts any canonical scalar",
        ));
    }
    let measure = matches!(function.as_str(), "sum" | "min" | "max" | "avg");
    let mut roots = HashSet::new();
    let mut sum = 0i64;
    let mut n = 0u64;
    let mut min = None;
    let mut max = None;
    for path in paths {
        if let Some(root) = path.first() {
            roots.insert(root.source_key.as_str());
        }
        if measure {
            if aggregation.property.is_empty() {
                return Err(ObjectLogCompareError::Unsupported(if function == "sum" {
                    "sum compare requires aggregation.property"
                } else {
                    "min, max, avg, and distinct compare require aggregation.property"
                }));
            }
            let leaf = path.last().ok_or(ObjectLogCompareError::Unsupported(
                "sum compare requires a leaf on every path",
            ))?;
            match leaf.properties.get(&aggregation.property) {
                None if function == "sum" => {
                    return Err(ObjectLogCompareError::Unsupported(
                        "sum property missing on a hop leaf; refusing vacuous compare",
                    ));
                }
                None => {}
                Some(raw) => {
                    if let Some(amount) = contributing_i64(&raw.as_cell())? {
                        sum = sum.wrapping_add(amount);
                        n += 1;
                        min = Some(min.map_or(amount, |seen: i64| seen.min(amount)));
                        max = Some(max.map_or(amount, |seen: i64| seen.max(amount)));
                    }
                }
            }
        }
    }
    if paths.len() != roots.len() {
        return Err(ObjectLogCompareError::Unsupported(
            "path multiplicity is not expressible on the tagged object-log evaluate API",
        ));
    }
    Ok(SqlLogSignature {
        roots: roots.len(),
        sum,
        n,
        min,
        max,
    })
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
    let function = aggregation.function.to_ascii_lowercase();
    let log = match with_object_log_store_cache(cache, path, |store| {
        ObjectSet::new(LocalCompute)
            .evaluate(store, &request)
            .map_err(|error| format!("{error:?}"))
    }) {
        Ok(log) => log,
        Err(error) if matches!(function.as_str(), "min" | "max") && error.contains("Overflow") => {
            return Err(ObjectLogCompareError::Unsupported(
                "SQL min/max do not share the object-log checked average overflow",
            ));
        }
        Err(error) => return Err(ObjectLogCompareError::Evaluate(error)),
    };
    let sql = sql_compare_signature(sql_paths, aggregation)?;
    let matched = match function.as_str() {
        "count" => sql.roots == log.two_hop_count,
        "sum" => {
            sql.roots == log.two_hop_count
                && (request.sum_property.is_empty() || sql.sum == log.sum_amount)
        }
        "min" | "max" | "avg" => {
            if sql.roots == 0 && log.two_hop_count == 0 && log.groups.is_empty() {
                true
            } else {
                match log.groups.first().filter(|_| log.groups.len() == 1) {
                    Some(group) => {
                        let aggregate_matches = match function.as_str() {
                            "min" => sql.min == group.min,
                            "max" => sql.max == group.max,
                            "avg" => (sql.sum, sql.n) == group.avg,
                            _ => false,
                        };
                        sql.roots == log.two_hop_count
                            && sql.roots == group.count
                            && aggregate_matches
                    }
                    None => false,
                }
            }
        }
        _ => false,
    };
    if matched {
        return Ok(());
    }
    Err(ObjectLogCompareError::Mismatch {
        sql_roots: sql.roots,
        sql_sum: sql.sum,
        log,
    })
}

/// Append an admitted object through tagged mikura ingest when the log lacks
/// this identity at the current property map. A receipted retry of the same
/// mutation does not bump generation. An update whose properties differ from
/// the stored record is appended.
///
/// Clerk admission and receipts stay here. The log owns identity generations.
/// Missing `SEKAI_OBJECT_LOG` (and no boot-installed path) skips ingest so
/// SQL-only fixtures keep working. A configured object-log host
/// (`SEKAI_OBJECT_LOG_HOST`, ADR 0088) owns the log instead: admits go
/// through it, and it is exclusive with a local log.
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
    ensure_admitted_object_in_log(&path, object).map(Some)
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
        .or_else(|| INSTALLED_LOG_PATH.get().cloned())
}

/// One generation of a named property on an identity, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyEditVersion {
    pub generation: u64,
    pub action_id: String,
    pub value: Option<String>,
    pub origin: &'static str,
}

/// Merge a sparse index edit into the live overlay, then persist it.
///
/// The local log is an exclusive writer, so load-merge-apply runs under the
/// cached store lock. SQL is the rebuildable projection of that result.
pub fn merge_and_apply_index_edit(
    sql_stored: Option<ObjectTypeIndexEdit>,
    mut incoming: ObjectTypeIndexEdit,
) -> Result<ObjectTypeIndexEdit, String> {
    if incoming.action_id.trim().is_empty() {
        incoming.action_id = overlay_action_id(&incoming);
    }
    if configured_log_host()?.is_none() && configured_log_path().is_none() {
        // Fixture path without a log. Production merge is fenced by the
        // object log; concurrent SQL-only puts are not recovered from it.
        return Ok(merge_index_edits(sql_stored, incoming));
    }
    ensure_overlay_identity(&incoming)?;
    if let Some(host) = configured_log_host()? {
        return merge_and_apply_on_host(&host, sql_stored, incoming);
    }
    let path = configured_log_path().ok_or_else(|| "object log path missing".to_string())?;
    with_cached_object_log_store(&path, |store| {
        merge_and_apply_on_store(store, sql_stored, incoming)
    })
}

fn load_store_overlay(
    store: &Store,
    namespace: &str,
    kind: &str,
    key: &str,
) -> Result<Option<ObjectTypeIndexEdit>, String> {
    match store.overlay(namespace, kind, key) {
        Ok(patch) => patch.map(edit_from_overlay).transpose(),
        Err(error) if error.contains("unknown namespace") || error.contains("unknown identity") => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn merge_and_apply_on_store(
    store: &mut Store,
    sql_stored: Option<ObjectTypeIndexEdit>,
    incoming: ObjectTypeIndexEdit,
) -> Result<ObjectTypeIndexEdit, String> {
    let expected_gen = live_record(
        store,
        &incoming.namespace,
        &incoming.kind,
        &incoming.source_key,
    )
    .map(|record| record.r#gen);
    let overlay = load_store_overlay(
        store,
        &incoming.namespace,
        &incoming.kind,
        &incoming.source_key,
    )?;
    let live = overlay.clone().or(sql_stored.clone());
    let merged = merge_index_edits(live.clone(), incoming.clone());
    let patch = overlay_patch_from_edit(&merged)?;
    match store.apply_overlay(patch, merged.action_id.clone(), expected_gen) {
        Ok(()) => Ok(merged),
        Err(error) if error.contains("body conflict") => {
            if incoming_matches_committed_action(store, &incoming)? {
                return Ok(load_store_overlay(
                    store,
                    &incoming.namespace,
                    &incoming.kind,
                    &incoming.source_key,
                )?
                .or(live)
                .unwrap_or(incoming));
            }
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn merge_and_apply_on_host(
    host: &crate::sekai::object_log_host::ObjectLogHost,
    sql_stored: Option<ObjectTypeIndexEdit>,
    incoming: ObjectTypeIndexEdit,
) -> Result<ObjectTypeIndexEdit, String> {
    let incoming_props = incoming.properties.clone();
    let incoming_hidden = incoming.hidden;
    for attempt in 0..8 {
        let expected_gen = host
            .load(&incoming.namespace, &incoming.kind, &incoming.source_key)?
            .map(|record| record.r#gen);
        let overlay =
            load_index_overlay(&incoming.namespace, &incoming.kind, &incoming.source_key)?;
        let merged = merge_index_edits(
            overlay.clone().or_else(|| sql_stored.clone()),
            incoming.clone(),
        );
        let patch = overlay_patch_from_edit(&merged)?;
        match host.apply_overlay(&patch, &merged.action_id, expected_gen) {
            Ok(()) => {
                let latest =
                    load_index_overlay(&incoming.namespace, &incoming.kind, &incoming.source_key)?;
                if latest.as_ref().is_some_and(|edit| {
                    incoming_props.iter().all(|(key, value)| {
                        edit.properties
                            .get(key)
                            .is_some_and(|stored| property_values_equivalent(stored, value))
                    }) && edit.hidden == incoming_hidden
                }) {
                    return Ok(merged);
                }
            }
            Err(error) if error.contains("stale generation") => {}
            Err(error) if error.contains("body conflict") => {
                // Host wire has no action-body history. A delayed retry is
                // accepted only when its properties and hidden still match
                // the live overlay.
                if overlay.as_ref().is_some_and(|stored| {
                    stored.hidden == incoming_hidden
                        && incoming_props.iter().all(|(key, value)| {
                            stored
                                .properties
                                .get(key)
                                .is_some_and(|cell| property_values_equivalent(cell, value))
                        })
                }) {
                    return Ok(overlay.or(sql_stored).unwrap_or(incoming));
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        if attempt == 7 {
            return Err("object-log host overlay merge lost an edit".into());
        }
    }
    Err("object-log host overlay merge lost an edit".into())
}

fn incoming_matches_committed_action(
    store: &Store,
    incoming: &ObjectTypeIndexEdit,
) -> Result<bool, String> {
    let versions = match store.history(
        &incoming.namespace,
        &incoming.kind,
        &incoming.source_key,
        &PropertyAcl::allow_all(),
    ) {
        Err(error) if error.contains("unknown identity") => return Ok(false),
        other => other?,
    };
    let Some(version) = versions
        .into_iter()
        .find(|version| version.record.action_id.as_deref() == Some(incoming.action_id.as_str()))
    else {
        return Ok(false);
    };
    let hidden = version
        .record
        .props
        .get(INDEX_HIDDEN_PROP)
        .map(|value| value == "1")
        .unwrap_or(version.record.hidden);
    Ok(hidden == incoming.hidden
        && incoming.properties.iter().all(|(key, value)| {
            version.record.props.get(key).is_some_and(|raw| {
                property_values_equivalent(&overlay_property_value(raw.clone()), value)
            })
        }))
}

/// Append the accumulated per-property overlay for an index edit.
///
/// No configured log is a no-op so SQL-only fixtures keep working.
pub fn apply_index_edit_overlay(edit: &ObjectTypeIndexEdit) -> Result<(), String> {
    if configured_log_host()?.is_none() && configured_log_path().is_none() {
        return Ok(());
    }
    let mut edit = edit.clone();
    if edit.action_id.trim().is_empty() {
        edit.action_id = overlay_action_id(&edit);
    }
    ensure_overlay_identity(&edit)?;
    let patch = overlay_patch_from_edit(&edit)?;
    if let Some(host) = configured_log_host()? {
        return host.apply_overlay(&patch, &edit.action_id, None);
    }
    let Some(path) = configured_log_path() else {
        return Ok(());
    };
    with_cached_object_log_store(&path, |store| {
        store.apply_overlay(patch, edit.action_id.clone(), None)
    })
}

/// Rewrite stored overlays after a type-revision rename. Same action_id with
/// a different patch fails closed, so each rewrite mints a rename action id.
///
/// Each identity is loaded from the live overlay and fenced with that
/// generation so a concurrent property edit is not overwritten by a stale
/// SQL snapshot.
pub fn rewrite_index_edit_overlays(
    edits: &mut [ObjectTypeIndexEdit],
    rename: &[(String, String)],
    revision: &str,
) -> Result<(), String> {
    if configured_log_host()?.is_none() && configured_log_path().is_none() {
        carry_index_edits(edits, rename, &[])?;
        return Ok(());
    }
    for edit in edits.iter_mut() {
        rewrite_one_index_edit_overlay(edit, rename, revision)?;
    }
    Ok(())
}

fn rewrite_one_index_edit_overlay(
    edit: &mut ObjectTypeIndexEdit,
    rename: &[(String, String)],
    revision: &str,
) -> Result<(), String> {
    ensure_overlay_identity(edit)?;
    if let Some(host) = configured_log_host()? {
        return rewrite_one_on_host(&host, edit, rename, revision);
    }
    let path = configured_log_path().ok_or_else(|| "object log path missing".to_string())?;
    with_cached_object_log_store(&path, |store| {
        rewrite_one_on_store(store, edit, rename, revision)
    })
}

fn rewrite_one_on_store(
    store: &mut Store,
    edit: &mut ObjectTypeIndexEdit,
    rename: &[(String, String)],
    revision: &str,
) -> Result<(), String> {
    let expected_gen = live_record(store, &edit.namespace, &edit.kind, &edit.source_key)
        .map(|record| record.r#gen);
    let overlay = load_store_overlay(store, &edit.namespace, &edit.kind, &edit.source_key)?;
    let mut next = overlay.unwrap_or_else(|| edit.clone());
    carry_index_edits(std::slice::from_mut(&mut next), rename, &[])?;
    next.action_id = rename_overlay_action_id(&next, rename, revision);
    let patch = overlay_patch_from_rename(&next, rename)?;
    store.apply_overlay(patch, next.action_id.clone(), expected_gen)?;
    *edit = next;
    Ok(())
}

fn rewrite_one_on_host(
    host: &crate::sekai::object_log_host::ObjectLogHost,
    edit: &mut ObjectTypeIndexEdit,
    rename: &[(String, String)],
    revision: &str,
) -> Result<(), String> {
    for attempt in 0..8 {
        let expected_gen = host
            .load(&edit.namespace, &edit.kind, &edit.source_key)?
            .map(|record| record.r#gen);
        let overlay = load_index_overlay(&edit.namespace, &edit.kind, &edit.source_key)?;
        let mut next = overlay.unwrap_or_else(|| edit.clone());
        carry_index_edits(std::slice::from_mut(&mut next), rename, &[])?;
        next.action_id = rename_overlay_action_id(&next, rename, revision);
        let patch = overlay_patch_from_rename(&next, rename)?;
        match host.apply_overlay(&patch, &next.action_id, expected_gen) {
            Ok(()) => {
                *edit = next;
                return Ok(());
            }
            Err(error) if error.contains("stale generation") => {}
            Err(error) => return Err(error),
        }
        if attempt == 7 {
            return Err("object-log host rename rewrite lost an edit".into());
        }
    }
    Err("object-log host rename rewrite lost an edit".into())
}

/// Latest overlay for each identity, projected as index edits.
pub fn load_index_overlays(
    namespace: &str,
    kind: &str,
    keys: &[String],
) -> Result<Vec<ObjectTypeIndexEdit>, String> {
    if configured_log_host()?.is_none() && configured_log_path().is_none() {
        return Ok(Vec::new());
    }
    let mut edits = Vec::new();
    for key in keys {
        if let Some(edit) = load_index_overlay(namespace, kind, key)? {
            edits.push(edit);
        }
    }
    Ok(edits)
}

/// History of one property of one identity, oldest first.
pub fn property_history(
    namespace: &str,
    kind: &str,
    key: &str,
    property: &str,
) -> Result<Vec<PropertyEditVersion>, String> {
    let path = configured_log_path()
        .ok_or_else(|| "property history requires a local object log".to_string())?;
    with_cached_object_log_store(&path, |store| {
        let versions = store.history(namespace, kind, key, &PropertyAcl::allow_all())?;
        Ok(versions
            .into_iter()
            .map(|version| PropertyEditVersion {
                generation: version.record.r#gen,
                action_id: version.record.action_id.clone().unwrap_or_default(),
                value: version
                    .record
                    .props
                    .get(property)
                    .map(|raw| overlay_property_display(raw)),
                origin: match version.origin {
                    VersionOrigin::Source => "source",
                    VersionOrigin::Edit => "edit",
                    VersionOrigin::Hide => "hide",
                },
            })
            .collect())
    })
}

const INDEX_HIDDEN_PROP: &str = "__sekai_index_hidden";
const INDEX_PROPERTY_TIMES_PROP: &str = "__sekai_index_property_times";

fn overlay_action_id(edit: &ObjectTypeIndexEdit) -> String {
    let body = serde_json::to_string(&(edit.hidden, edit.edited_at_ms, &edit.properties))
        .unwrap_or_default();
    format!(
        "put-index-edit:{}/{}/{}:{}",
        edit.namespace,
        edit.kind,
        edit.source_key,
        crate::sekai::embedding_index::sha_hex(&body)
    )
}

fn rename_overlay_action_id(
    edit: &ObjectTypeIndexEdit,
    rename: &[(String, String)],
    revision: &str,
) -> String {
    let body = serde_json::to_string(&(revision, rename, &edit.properties)).unwrap_or_default();
    format!(
        "type-revision-rename:{}/{}/{}:{}",
        edit.namespace,
        edit.kind,
        edit.source_key,
        crate::sekai::embedding_index::sha_hex(&body)
    )
}

fn overlay_property_value(raw: String) -> PropertyValue {
    // OverlayPatch.props are clerk cells. Declared types are restored by
    // coerce_index_edit before the SQL index persists the merged edit.
    PropertyValue::String(raw)
}

fn overlay_property_display(raw: &str) -> String {
    raw.to_string()
}

fn overlay_patch_from_edit(edit: &ObjectTypeIndexEdit) -> Result<OverlayPatch, String> {
    overlay_patch_from_edit_cleared(edit, Vec::new())
}

fn overlay_patch_from_rename(
    edit: &ObjectTypeIndexEdit,
    rename: &[(String, String)],
) -> Result<OverlayPatch, String> {
    overlay_patch_from_edit_cleared(
        edit,
        rename
            .iter()
            .filter(|(old, new)| old != new)
            .map(|(old, _)| old.clone())
            .collect(),
    )
}

fn overlay_patch_from_edit_cleared(
    edit: &ObjectTypeIndexEdit,
    cleared: Vec<String>,
) -> Result<OverlayPatch, String> {
    let mut props = HashMap::new();
    for (key, value) in &edit.properties {
        props.insert(key.clone(), value.as_cell());
    }
    props.insert(
        INDEX_HIDDEN_PROP.into(),
        if edit.hidden { "1" } else { "0" }.into(),
    );
    if !edit.property_edited_at_ms.is_empty() {
        props.insert(
            INDEX_PROPERTY_TIMES_PROP.into(),
            serde_json::to_string(&edit.property_edited_at_ms)
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(OverlayPatch {
        namespace: edit.namespace.clone(),
        kind: edit.kind.clone(),
        key: edit.source_key.clone(),
        props,
        cleared,
        action_id: None,
        at: Some(overlay_at_rfc3339(edit.edited_at_ms)),
    })
}

fn overlay_at_rfc3339(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms.max(0))
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn overlay_at_millis(raw: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|value| value.timestamp_millis())
        .unwrap_or(0)
}

fn edit_from_overlay(patch: OverlayPatch) -> Result<ObjectTypeIndexEdit, String> {
    let mut properties: BTreeMap<String, String> = patch.props.into_iter().collect();
    let hidden = properties
        .remove(INDEX_HIDDEN_PROP)
        .is_some_and(|value| value == "1");
    let property_edited_at_ms = match properties.remove(INDEX_PROPERTY_TIMES_PROP) {
        Some(raw) => parse_property_edit_times(&raw)?,
        None => BTreeMap::new(),
    };
    let properties = properties
        .into_iter()
        .map(|(key, value)| (key, overlay_property_value(value)))
        .collect();
    Ok(ObjectTypeIndexEdit {
        namespace: patch.namespace,
        kind: patch.kind,
        source_key: patch.key,
        properties,
        hidden,
        action_id: patch.action_id.unwrap_or_default(),
        edited_at_ms: patch.at.as_deref().map(overlay_at_millis).unwrap_or(0),
        property_edited_at_ms,
    })
}

fn ensure_overlay_identity(edit: &ObjectTypeIndexEdit) -> Result<(), String> {
    if overlay_identity_exists(&edit.namespace, &edit.kind, &edit.source_key)? {
        return Ok(());
    }
    let object = Object {
        id: edit.source_key.clone(),
        kind: edit.kind.clone(),
        name: edit.source_key.clone(),
        namespace: edit.namespace.clone(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: edit.edited_at_ms.max(1),
        updated: edit.edited_at_ms.max(1),
    };
    ensure_admitted_object_in_configured_log(&object).map(|_| ())
}

fn overlay_identity_exists(namespace: &str, kind: &str, key: &str) -> Result<bool, String> {
    if let Some(host) = configured_log_host()? {
        return host
            .load(namespace, kind, key)
            .map(|record| record.is_some());
    }
    let Some(path) = configured_log_path() else {
        return Ok(false);
    };
    with_cached_object_log_store(&path, |store| {
        Ok(live_record(store, namespace, kind, key).is_some())
    })
}

fn load_index_overlay(
    namespace: &str,
    kind: &str,
    key: &str,
) -> Result<Option<ObjectTypeIndexEdit>, String> {
    if let Some(host) = configured_log_host()? {
        let Some(record) = host.load(
            namespace,
            mikura::OVERLAY_KIND,
            &OverlayPatch::identity_key(kind, key),
        )?
        else {
            return Ok(None);
        };
        return OverlayPatch::from_record(&record)
            .and_then(edit_from_overlay)
            .map(Some);
    }
    let Some(path) = configured_log_path() else {
        return Ok(None);
    };
    with_cached_object_log_store(&path, |store| match store.overlay(namespace, kind, key) {
        Ok(patch) => patch.map(edit_from_overlay).transpose(),
        Err(error) if error.contains("unknown namespace") || error.contains("unknown identity") => {
            Ok(None)
        }
        Err(error) => Err(error),
    })
}

/// Record the local log path Combined/Sekai boot opened so later admits
/// write the same file without requiring the operator to set `SEKAI_OBJECT_LOG`.
pub fn install_process_log_path(path: PathBuf) {
    let _ = INSTALLED_LOG_PATH.set(path);
}

/// Open or create the local log and keep the exclusive writer for this process.
pub fn hold_local_log(path: &Path) -> Result<(), String> {
    with_object_log_store_cache(
        OBJECT_LOG_STORE.get_or_init(|| Mutex::new(None)),
        path,
        |_| Ok(()),
    )
}

fn backfill_marker_path(log: &Path) -> PathBuf {
    let mut name = log
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| DEFAULT_LOG_FILE.into());
    name.push(BACKFILL_MARKER_SUFFIX);
    log.with_file_name(name)
}

/// True when a previous complete scan wrote the marker next to a populated
/// log. An orphaned marker beside an empty replacement log is removed so a
/// kill after the first recovered object cannot treat the partial rebuild
/// as complete.
pub fn backfill_already_complete(path: &Path) -> Result<bool, String> {
    let marker = backfill_marker_path(path);
    if !marker.exists() {
        return Ok(false);
    }
    let populated = with_cached_object_log_store(path, |store| Ok(store.committed_pages() > 0))?;
    if populated {
        return Ok(true);
    }
    std::fs::remove_file(&marker).map_err(|error| error.to_string())?;
    Ok(false)
}

fn log_can_own_identity(object: &Object) -> bool {
    !object.namespace.trim().is_empty()
        && !object.kind.trim().is_empty()
        && !object.id.trim().is_empty()
}

/// Ingest recorded objects into `path` when the identity is absent. An
/// identity already in the log keeps its generation, so a concurrent admit
/// of newer properties is not overwritten by a boot snapshot. A kill
/// mid-run and a retry match an uninterrupted pass. Writes the complete
/// marker only after every object. An orphaned marker next to an empty
/// replacement log does not skip recovery. Internal SQL records with an
/// empty namespace are skipped: mikura refuses them, and they must not
/// fail Combined/Sekai boot.
pub fn backfill_recorded_objects<'a>(
    path: &Path,
    objects: impl IntoIterator<Item = &'a Object>,
) -> Result<usize, String> {
    if backfill_already_complete(path)? {
        return Ok(0);
    }
    let mut count = 0;
    for object in objects {
        if ingest_absent_identity(path, object)?.is_some() {
            count += 1;
        }
    }
    std::fs::write(backfill_marker_path(path), format!("{count}\n"))
        .map_err(|error| error.to_string())?;
    Ok(count)
}

/// Append only when the log has never committed this identity.
pub fn ingest_absent_identity(path: &Path, object: &Object) -> Result<Option<u64>, String> {
    if !log_can_own_identity(object) {
        return Ok(None);
    }
    if path.exists() {
        let present = with_cached_object_log_store(path, |store| {
            Ok(store
                .load(
                    &object.namespace,
                    &object.kind,
                    &object.id,
                    &PropertyAcl::allow_all(),
                )
                .ok()
                .is_some())
        })?;
        if present {
            return Ok(None);
        }
    }
    apply_admitted_object_to_log(path, object)
        .map(Some)
        .map_err(|error| {
            // The pinned log stores one record per 4KiB page. An oversized
            // SQL object fails closed with its identity; skipping would
            // leave identity only in the projection.
            if error.contains("larger than a page") {
                format!(
                    "object {}/{}/{} exceeds the object-log page: {error}",
                    object.namespace, object.kind, object.id
                )
            } else {
                error
            }
        })
}

/// Append when the log lacks this identity at the current property map.
pub fn ensure_admitted_object_in_log(path: &Path, object: &Object) -> Result<u64, String> {
    if path.exists() {
        let existing = with_cached_object_log_store(path, |store| {
            Ok(
                visible_record(store, &object.namespace, &object.kind, &object.id)
                    .filter(|record| record.props == object.properties)
                    .map(|record| record.r#gen),
            )
        });
        if let Ok(Some(generation)) = existing {
            return Ok(generation);
        }
    }
    apply_admitted_object_to_log(path, object)
}

#[cfg(test)]
pub struct TestLogPathGuard;

#[cfg(test)]
impl Drop for TestLogPathGuard {
    fn drop(&mut self) {
        TEST_LOG_PATH.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

#[cfg(test)]
pub fn enter_test_log_path(path: &Path) -> TestLogPathGuard {
    TEST_LOG_PATH.with(|slot| {
        *slot.borrow_mut() = Some(path.to_path_buf());
    });
    TestLogPathGuard
}

#[cfg(test)]
pub fn with_test_log_path<R>(path: &Path, body: impl FnOnce() -> R) -> R {
    let _guard = enter_test_log_path(path);
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
        let led = with_cached_object_log(cache, path, |cached| {
            opened = true;
            commit_queued(cached, queue, path)
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
fn commit_queued(
    cached: &mut CachedObjectLogStore,
    queue: &IngestQueue,
    path: &Path,
) -> Result<(), String> {
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
            if !seen.insert((
                ticket.object.namespace.clone(),
                ticket.object.kind.clone(),
                ticket.object.id.clone(),
            )) {
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
        identity_generation(
            store,
            &ticket.object.namespace,
            &ticket.object.kind,
            &ticket.object.id,
        )
    };
    let pages_before = cached.store_mut()?.committed_pages();
    let records = batch
        .iter()
        .map(|ticket| object_record(&ticket.object))
        .collect::<Vec<_>>();
    let Err(error) = run_batch(cached.store_mut()?, records) else {
        let store = cached.store_mut()?;
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
    // Drop the exclusive handle before opening again (mikura v0.5.0).
    let reopened = match cached.reopen() {
        Ok(reopened) => reopened,
        Err(reopen) => {
            for ticket in &batch {
                ticket.finish(Err(format!("{error}; reopening the log failed: {reopen}")));
            }
            return Err(error);
        }
    };
    let committed = reopened.committed_pages() > pages_before;
    for (index, ticket) in batch.iter().enumerate() {
        if committed {
            ticket.finish(generation(cached.store_mut()?, ticket));
            continue;
        }
        // A rolled-back batch retries each record alone, so one bad record
        // cannot fail the rest. A failed retry reopens the handle before the
        // next record, since a failed write can leave it inconsistent.
        let outcome = {
            let store = cached.store_mut()?;
            mikura_ingest::BatchIngest::run(store, vec![object_record(&ticket.object)])
                .and_then(|()| generation(store, ticket))
        };
        if outcome.is_err()
            && let Err(reopen) = cached.reopen()
        {
            ticket.finish(outcome);
            for rest in &batch[index + 1..] {
                rest.finish(Err(format!("{error}; reopening the log failed: {reopen}")));
            }
            return Err(error);
        }
        ticket.finish(outcome);
    }
    // Drop the handle after any failed batch, as a single-record failure
    // always has.
    Err(error)
}

/// Resolve one V1 `(kind, key)` to a plane namespace from the SQL projection.
/// Unknown identities and collisions fail closed (ADR 0112).
pub fn projection_namespace_for(
    rows: &[(String, String, String)],
    kind: &str,
    key: &str,
) -> Result<String, String> {
    let mut found = None;
    for (namespace, row_kind, row_key) in rows {
        if row_kind != kind || row_key != key {
            continue;
        }
        match &found {
            None => found = Some(namespace.clone()),
            Some(existing) if existing == namespace => {}
            Some(existing) => {
                return Err(format!(
                    "{kind}/{key} is in more than one namespace ({existing} and {namespace})"
                ));
            }
        }
    }
    found.ok_or_else(|| format!("{kind}/{key} is unknown to the object projection"))
}

/// Copy a `MIKURAV1` log to a namespaced `MIKURAV2` log. `src` is only read.
pub fn migrate_unnamespaced_object_log(
    src: &Path,
    dst: &Path,
    mut namespace_for: impl FnMut(&str, &str) -> Result<String, String>,
) -> Result<usize, String> {
    Store::migrate_unnamespaced_with(src, dst, |kind, key| namespace_for(kind, key))
}

/// Assign each V1 identity its plane namespace from SQL projection rows
/// `(namespace, kind, source_key)`.
pub fn migrate_unnamespaced_object_log_from_projection(
    src: &Path,
    dst: &Path,
    rows: &[(String, String, String)],
) -> Result<usize, String> {
    migrate_unnamespaced_object_log(src, dst, |kind, key| {
        projection_namespace_for(rows, kind, key)
    })
}

fn object_record(object: &Object) -> ObjectRecord {
    ObjectRecord {
        r#gen: 0,
        namespace: object.namespace.clone(),
        kind: object.kind.clone(),
        key: object.id.clone(),
        hidden: false,
        // Admission ingest carries no mikura Action id; ingest idempotency
        // stays the receipted clerk admission.
        action_id: None,
        props: object.properties.clone(),
        schema_version: 1,
    }
}

pub fn identity_generation(
    store: &Store,
    namespace: &str,
    kind: &str,
    key: &str,
) -> Result<u64, String> {
    visible_record(store, namespace, kind, key)
        .map(|record| record.r#gen)
        .ok_or_else(|| format!("mikura identity missing for {namespace}/{kind}:{key}"))
}

/// The current visible record for one identity, by direct lookup. Missing or
/// hidden identities read as absent, as the v0.1 visible-kind scan did.
fn live_record(store: &Store, namespace: &str, kind: &str, key: &str) -> Option<ObjectRecord> {
    store
        .load(namespace, kind, key, &PropertyAcl::allow_all())
        .ok()
}

fn visible_record(store: &Store, namespace: &str, kind: &str, key: &str) -> Option<ObjectRecord> {
    live_record(store, namespace, kind, key).filter(|record| !record.hidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_cells_keep_legacy_literals_and_round_trip_typed_values() {
        assert_eq!(
            overlay_property_value(r#""hello""#.into()),
            PropertyValue::String(r#""hello""#.into())
        );
        assert_eq!(
            overlay_property_value("edited".into()),
            PropertyValue::String("edited".into())
        );
        assert_eq!(
            overlay_property_value("true".into()),
            PropertyValue::String("true".into())
        );
        assert_eq!(PropertyValue::Bool(true).as_cell(), "true");
        assert_eq!(PropertyValue::Int(12).as_cell(), "12");
        assert!(property_values_equivalent(
            &overlay_property_value("12".into()),
            &PropertyValue::Int(12)
        ));
        assert_eq!(overlay_property_display("edited"), "edited");
        assert_eq!(overlay_property_display("12"), "12");
    }

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
        let installed = PathBuf::from("data/objects.mikura");
        let dual = ObjectLogDualRead::resolve(Some("1".into()), None, None, None)
            .with_default_log(Some(installed.clone()), false);
        assert_eq!(dual.log_path, Some(installed));
        let hosted =
            ObjectLogDualRead::resolve(Some("1".into()), None, None, Some("127.0.0.1:7070".into()))
                .with_default_log(Some(PathBuf::from("data/objects.mikura")), true);
        assert_eq!(hosted.log_path, None);
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
        with_cached_object_log_store(&log, |store| {
            assert_eq!(
                identity_generation(store, "sales", "Customer", "c1").unwrap(),
                2
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn a_second_store_on_the_same_path_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        hold_local_log(&log).unwrap();
        let error = match Store::open(&log) {
            Ok(_) => panic!("second writer must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.contains(mikura::LOG_IN_USE),
            "second writer must fail closed: {error}"
        );
        release_process_object_log_cache();
        drop(Store::open(&log).expect("exclusive lock released"));
    }

    fn sample_object(id: &str, region: &str) -> Object {
        Object {
            id: id.into(),
            kind: "Customer".into(),
            name: id.into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: HashMap::from([("region".into(), region.into())]),
            created: 1,
            updated: 1,
        }
    }

    fn log_generations(path: &Path, ids: &[&str]) -> Vec<u64> {
        with_cached_object_log_store(path, |store| {
            ids.iter()
                .map(|id| identity_generation(store, "sales", "Customer", id))
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap()
    }

    #[test]
    fn backfill_killed_midway_matches_an_uninterrupted_run() {
        let dir = tempfile::tempdir().unwrap();
        let interrupted = dir.path().join("interrupted.mikura");
        let complete = dir.path().join("complete.mikura");
        let objects = [
            sample_object("a", "eu"),
            sample_object("b", "us"),
            sample_object("c", "ap"),
        ];
        backfill_recorded_objects(&complete, objects.iter()).unwrap();
        release_process_object_log_cache();
        ensure_admitted_object_in_log(&interrupted, &objects[0]).unwrap();
        release_process_object_log_cache();
        backfill_recorded_objects(&interrupted, objects.iter()).unwrap();
        let ids = ["a", "b", "c"];
        assert_eq!(
            log_generations(&interrupted, &ids),
            log_generations(&complete, &ids)
        );
        assert_eq!(
            backfill_recorded_objects(&interrupted, objects.iter()).unwrap(),
            0,
            "complete marker skips a second scan"
        );
    }

    #[test]
    fn backfill_does_not_replace_a_newer_log_identity() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        apply_admitted_object_to_log(&log, &sample_object("a", "us")).unwrap();
        backfill_recorded_objects(&log, std::iter::once(&sample_object("a", "eu"))).unwrap();
        assert_eq!(log_generations(&log, &["a"]), vec![1]);
        with_cached_object_log_store(&log, |store| {
            let record = visible_record(store, "sales", "Customer", "a").unwrap();
            assert_eq!(record.props.get("region").map(String::as_str), Some("us"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn backfill_does_not_unhide_an_existing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut store = Store::create(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![ObjectRecord {
                action_id: None,
                r#gen: 1,
                namespace: "sales".into(),
                kind: "Customer".into(),
                key: "a".into(),
                hidden: true,
                props: HashMap::from([("region".into(), "us".into())]),
                schema_version: 1,
            }],
        )
        .unwrap();
        drop(store);
        backfill_recorded_objects(&log, std::iter::once(&sample_object("a", "eu"))).unwrap();
        with_cached_object_log_store(&log, |store| {
            let record = store
                .load("sales", "Customer", "a", &PropertyAcl::allow_all())
                .unwrap();
            assert!(record.hidden);
            assert_eq!(record.r#gen, 1);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn backfill_fails_closed_when_a_record_exceeds_a_page() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut object = sample_object("huge", "eu");
        object.properties.insert("blob".into(), "x".repeat(8000));
        let error = backfill_recorded_objects(&log, std::iter::once(&object)).unwrap_err();
        assert!(error.contains("huge"), "{error}");
        assert!(error.contains("page"), "{error}");
    }

    #[test]
    fn backfill_skips_internal_objects_with_empty_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let internal = Object {
            id: "rule-1".into(),
            kind: "TrustScoreRule".into(),
            name: "rule".into(),
            namespace: String::new(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        assert!(
            apply_admitted_object_to_log(&log, &internal)
                .unwrap_err()
                .contains("namespace"),
            "mikura must refuse empty-namespace internals"
        );
        let named = sample_object("a", "eu");
        assert_eq!(
            backfill_recorded_objects(&log, [&internal, &named].into_iter()).unwrap(),
            1
        );
        assert_eq!(log_generations(&log, &["a"]), vec![1]);
        assert!(backfill_already_complete(&log).unwrap());
    }

    #[test]
    fn an_orphaned_marker_does_not_complete_a_partial_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let objects = [sample_object("a", "eu"), sample_object("b", "us")];
        backfill_recorded_objects(&log, objects.iter()).unwrap();
        release_process_object_log_cache();
        std::fs::remove_file(&log).unwrap();
        hold_local_log(&log).unwrap();
        assert!(!backfill_already_complete(&log).unwrap());
        assert!(!backfill_marker_path(&log).exists());
        ingest_absent_identity(&log, &objects[0]).unwrap();
        backfill_recorded_objects(&log, objects.iter()).unwrap();
        assert_eq!(log_generations(&log, &["a", "b"]), vec![1, 1]);
    }

    #[test]
    fn an_orphaned_backfill_marker_does_not_skip_an_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let objects = [sample_object("a", "eu")];
        backfill_recorded_objects(&log, objects.iter()).unwrap();
        release_process_object_log_cache();
        std::fs::remove_file(&log).unwrap();
        assert!(backfill_marker_path(&log).exists());
        hold_local_log(&log).unwrap();
        backfill_recorded_objects(&log, objects.iter()).unwrap();
        assert_eq!(log_generations(&log, &["a"]), vec![1]);
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
                identity_generation(store, &object.namespace, &object.kind, &object.id)
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

        // A failed operation discards the writer (not failure-atomic) then
        // immediately reopens so the exclusive lock stays with this process.
        let failing = with_object_log_store_cache(&cache, &log, |_store| {
            Err::<(), _>("injected failure".to_string())
        });
        assert!(failing.is_err());
        assert_eq!(OBJECT_LOG_STORE_OPENS.with(|opens| opens.get()), 4);
        match Store::open(&log) {
            Ok(_) => panic!("second writer must fail closed while the process holds the log"),
            Err(error) => assert!(
                error.contains(mikura::LOG_IN_USE),
                "unexpected second-open error: {error}"
            ),
        }
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

                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    key: "c1".into(),
                    hidden: false,
                    props: HashMap::from([("n".into(), generation.to_string())]),

                    schema_version: 1,
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
        let pages_before =
            with_object_log_store_cache(&cache, &path, |store| Ok(store.committed_pages()))
                .unwrap();
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
        with_object_log_store_cache(&cache, &path, |store| {
            assert_eq!(store.committed_pages(), pages_before + 1);
            for (id, generation) in ["q1", "q2", "q3", "q4", "leader"].iter().zip(&generations) {
                assert_eq!(
                    identity_generation(store, "sales", "Customer", id).unwrap(),
                    *generation
                );
            }
            Ok(())
        })
        .unwrap();
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
        let pages_before =
            with_object_log_store_cache(&cache, &path, |store| Ok(store.committed_pages()))
                .unwrap();
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
        let pages_after =
            with_object_log_store_cache(&cache, &path, |store| Ok(store.committed_pages()))
                .unwrap();
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
                identity_generation(&store, "sales", "Customer", id).unwrap(),
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
                identity_generation(&store, "sales", "Customer", id).unwrap(),
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
        with_object_log_store_cache(&cache, &path, |store| {
            assert_eq!(
                identity_generation(store, "sales", "Customer", "twin").unwrap(),
                newer
            );
            Ok(())
        })
        .unwrap();
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
        release_process_object_log_cache();
        let store = Store::open(&path).unwrap();
        assert_eq!(results.len(), 80);
        for (id, generation) in &results {
            assert_eq!(
                identity_generation(&store, "sales", "Customer", id).unwrap(),
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

                    namespace: "sales".into(),
                    kind: "Customer".into(),
                    key: "c1".into(),
                    hidden: false,
                    props: HashMap::from([("region".into(), "eu".into())]),

                    schema_version: 1,
                },
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,

                    namespace: "sales".into(),
                    kind: "Order".into(),
                    key: "o1".into(),
                    hidden: false,
                    props: HashMap::from([("customer_id".into(), "c1".into())]),

                    schema_version: 1,
                },
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,

                    namespace: "sales".into(),
                    kind: "Shipment".into(),
                    key: "s1".into(),
                    hidden: false,
                    props: HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "10".into()),
                    ]),

                    schema_version: 1,
                },
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,

                    namespace: "sales".into(),
                    kind: "Shipment".into(),
                    key: "s-hidden".into(),
                    hidden: true,
                    props: HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "99".into()),
                    ]),

                    schema_version: 1,
                },
            ],
        )
        .unwrap();
        drop(store);
        let descriptor = ObjectSetDescriptor {
            namespace: "sales".into(),
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

        // mikura v0.5.0 holds an exclusive writer: an out-of-band ingest
        // drops that handle first, then the next sample opens fresh.
        release_object_log_cache(&cache);
        let mut store = Store::open(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![ObjectRecord {
                action_id: None,
                r#gen: 1,

                namespace: "sales".into(),
                kind: "Shipment".into(),
                key: "s2".into(),
                hidden: false,
                props: HashMap::from([
                    ("order_id".into(), "o1".into()),
                    ("amount".into(), "5".into()),
                ]),

                schema_version: 1,
            }],
        )
        .unwrap();
        drop(store);
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
            namespace: "sales".into(),
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

    fn member_props(kind: &str, key: &str, properties: &[(&str, &str)]) -> ObjectTypeIndexMember {
        ObjectTypeIndexMember {
            kind: kind.into(),
            source_key: key.into(),
            object_id: format!("{kind}:{key}"),
            properties: properties
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),
            ..ObjectTypeIndexMember::default()
        }
    }

    fn shop_view() -> PropertyAcl {
        let mut acl = PropertyAcl::allow_all();
        acl.insert_row_filter("order", "status", ["open", "closed"])
            .unwrap();
        acl
    }

    fn shop_order_record(
        key: &str,
        customer: &str,
        status: &str,
        priority: &str,
        owner: &str,
        amount: &str,
    ) -> ObjectRecord {
        let mut props = HashMap::from([
            ("customer".into(), customer.into()),
            ("status".into(), status.into()),
            ("amount".into(), amount.into()),
        ]);
        if !priority.is_empty() {
            props.insert("priority".into(), priority.into());
        }
        if !owner.is_empty() {
            props.insert("owner".into(), owner.into());
        }
        ObjectRecord {
            action_id: None,
            r#gen: 1,
            namespace: "shop".into(),
            kind: "order".into(),
            key: key.into(),
            hidden: false,
            props,
            schema_version: 1,
        }
    }

    fn seed_shop_log(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join(name);
        let mut store = Store::create(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![
                shop_order_record("o1", "c1", "open", "2", "ann", "10"),
                shop_order_record("o2", "c1", "closed", "1", "ann", "7"),
                shop_order_record("o3", "c2", "open", "3", "bob", "4"),
                shop_order_record("o4", "c3", "open", "", "bob", ""),
                shop_order_record("o5", "c3", "closed", "2", "cid", "x12"),
                shop_order_record("o6", "c4", "open", "1", "ann", "-3"),
                shop_order_record("o7", "c2", "open", "2", "", "10"),
                shop_order_record("o8", "c1", "archived", "1", "bob", "1000"),
            ],
        )
        .unwrap();
        for (key, region) in [
            ("c1", Some("east")),
            ("c2", Some("west")),
            ("c3", Some("east")),
            ("c4", None),
            ("c5", Some("west")),
        ] {
            let props = region
                .map(|value| HashMap::from([("region".into(), value.into())]))
                .unwrap_or_default();
            BatchIngest::run(
                &mut store,
                vec![ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "shop".into(),
                    kind: "customer".into(),
                    key: key.into(),
                    hidden: false,
                    props,
                    schema_version: 1,
                }],
            )
            .unwrap();
        }
        (dir, log)
    }

    fn shop_visible_orders() -> Vec<ObjectTypeIndexMember> {
        vec![
            member_props(
                "order",
                "o1",
                &[
                    ("customer", "c1"),
                    ("status", "open"),
                    ("priority", "2"),
                    ("owner", "ann"),
                    ("amount", "10"),
                ],
            ),
            member_props(
                "order",
                "o2",
                &[
                    ("customer", "c1"),
                    ("status", "closed"),
                    ("priority", "1"),
                    ("owner", "ann"),
                    ("amount", "7"),
                ],
            ),
            member_props(
                "order",
                "o3",
                &[
                    ("customer", "c2"),
                    ("status", "open"),
                    ("priority", "3"),
                    ("owner", "bob"),
                    ("amount", "4"),
                ],
            ),
            member_props(
                "order",
                "o4",
                &[
                    ("customer", "c3"),
                    ("status", "open"),
                    ("owner", "bob"),
                    ("amount", ""),
                ],
            ),
            member_props(
                "order",
                "o5",
                &[
                    ("customer", "c3"),
                    ("status", "closed"),
                    ("priority", "2"),
                    ("owner", "cid"),
                    ("amount", "x12"),
                ],
            ),
            member_props(
                "order",
                "o6",
                &[
                    ("customer", "c4"),
                    ("status", "open"),
                    ("priority", "1"),
                    ("owner", "ann"),
                    ("amount", "-3"),
                ],
            ),
            member_props(
                "order",
                "o7",
                &[
                    ("customer", "c2"),
                    ("status", "open"),
                    ("priority", "2"),
                    ("amount", "10"),
                ],
            ),
        ]
    }

    fn shop_order_descriptor() -> ObjectSetDescriptor {
        ObjectSetDescriptor {
            namespace: "shop".into(),
            kind: "order".into(),
            ..ObjectSetDescriptor::default()
        }
    }

    fn fixture_agg(function: &str, property: &str) -> ObjectSetAggregation {
        ObjectSetAggregation {
            function: function.into(),
            property: property.into(),
            group_by: String::new(),
        }
    }

    fn compare_shop(
        log: &std::path::Path,
        aggregation: &ObjectSetAggregation,
        orders: &[ObjectTypeIndexMember],
        acl: PropertyAcl,
    ) -> Result<(), ObjectLogCompareError> {
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        let paths: Vec<Vec<&ObjectTypeIndexMember>> =
            orders.iter().map(|order| vec![order]).collect();
        compare_sql_to_log_with_cache(
            &cache,
            log,
            &shop_order_descriptor(),
            &[],
            aggregation,
            &paths,
            acl,
        )
    }

    #[test]
    fn fixture_a1_count_sum_min_max_avg_match_without_group_by() {
        let (_dir, log) = seed_shop_log("fixture-a1.mikura");
        let orders = shop_visible_orders();
        let acl = shop_view();
        compare_shop(&log, &fixture_agg("count", ""), &orders, acl.clone()).unwrap();
        compare_shop(&log, &fixture_agg("sum", "amount"), &orders, acl.clone()).unwrap();
        compare_shop(&log, &fixture_agg("min", "amount"), &orders, acl.clone()).unwrap();
        compare_shop(&log, &fixture_agg("max", "amount"), &orders, acl.clone()).unwrap();
        compare_shop(&log, &fixture_agg("avg", "amount"), &orders, acl).unwrap();
    }

    #[test]
    fn empty_min_max_avg_match_when_both_sides_are_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("fixture-empty.mikura");
        let mut store = Store::create(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![ObjectRecord {
                action_id: None,
                r#gen: 1,
                namespace: "shop".into(),
                kind: "customer".into(),
                key: "c1".into(),
                hidden: false,
                props: HashMap::new(),
                schema_version: 1,
            }],
        )
        .unwrap();
        drop(store);
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        let descriptor = shop_order_descriptor();
        let paths: [Vec<&ObjectTypeIndexMember>; 0] = [];
        for function in ["min", "max", "avg"] {
            compare_sql_to_log_with_cache(
                &cache,
                &log,
                &descriptor,
                &[],
                &fixture_agg(function, "amount"),
                &paths,
                PropertyAcl::allow_all(),
            )
            .unwrap();
        }
    }

    #[test]
    fn fixture_a2_a3_string_distinct_refuses_numeric_only_sql() {
        let orders = shop_visible_orders();
        let paths: Vec<Vec<&ObjectTypeIndexMember>> =
            orders.iter().map(|order| vec![order]).collect();
        let err = sql_compare_signature(&paths, &fixture_agg("distinct", "owner")).unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("numeric"))
        );
        let mapped = map_evaluate_request(
            &shop_order_descriptor(),
            &[],
            &fixture_agg("distinct", "status"),
            shop_view(),
        )
        .unwrap();
        assert_eq!(
            mapped
                .breakdown
                .as_ref()
                .and_then(|b| b.distinct.as_deref()),
            Some("status")
        );
        let (_dir, log) = seed_shop_log("fixture-a3.mikura");
        let orders = shop_visible_orders();
        let err = compare_shop(
            &log,
            &fixture_agg("distinct", "status"),
            &orders,
            shop_view(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("numeric"))
        );
    }

    #[test]
    fn fixture_group_by_and_h1_refuse_absent_key_fallback() {
        for group_by in ["status", "owner", "region"] {
            let err = map_evaluate_request(
                &shop_order_descriptor(),
                &[],
                &ObjectSetAggregation {
                    function: "sum".into(),
                    property: "amount".into(),
                    group_by: group_by.into(),
                },
                shop_view(),
            )
            .unwrap_err();
            assert!(
                matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("absent group"))
            );
        }
        let err = map_evaluate_request(
            &ObjectSetDescriptor {
                namespace: "shop".into(),
                kind: "customer".into(),
                ..ObjectSetDescriptor::default()
            },
            &[crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "order".into(),
                join_property: "customer".into(),
                ..Default::default()
            }],
            &ObjectSetAggregation {
                function: "sum".into(),
                property: "amount".into(),
                group_by: "region".into(),
            },
            shop_view(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("absent group"))
        );
    }

    #[test]
    fn fixture_sort_queries_refuse_one_key_sql_order_by() {
        let mut descriptor = shop_order_descriptor();
        descriptor.order_by = "property:status".into();
        let err = map_evaluate_request(&descriptor, &[], &fixture_agg("count", ""), shop_view())
            .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("three keys"))
        );
    }

    #[test]
    fn fixture_d1_denied_owner_fails_closed_on_distinct() {
        let (_dir, log) = seed_shop_log("fixture-d1.mikura");
        let mut acl = shop_view();
        acl.insert_deny("order", "owner").unwrap();
        let orders = shop_visible_orders();
        let err = compare_shop(&log, &fixture_agg("distinct", "owner"), &orders, acl).unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Evaluate(message) if message.contains("Denied"))
        );
    }

    #[test]
    fn fixture_o1_avg_overflows_and_o2_sum_wraps() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("fixture-ovf.mikura");
        let mut store = Store::create(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "ovf".into(),
                    kind: "order".into(),
                    key: "o1".into(),
                    hidden: false,
                    props: HashMap::from([("amount".into(), "9223372036854775807".into())]),
                    schema_version: 1,
                },
                ObjectRecord {
                    action_id: None,
                    r#gen: 1,
                    namespace: "ovf".into(),
                    kind: "order".into(),
                    key: "o2".into(),
                    hidden: false,
                    props: HashMap::from([("amount".into(), "1".into())]),
                    schema_version: 1,
                },
            ],
        )
        .unwrap();
        drop(store);
        let members = [
            member_props("order", "o1", &[("amount", "9223372036854775807")]),
            member_props("order", "o2", &[("amount", "1")]),
        ];
        let paths: Vec<Vec<&ObjectTypeIndexMember>> = members.iter().map(|row| vec![row]).collect();
        let descriptor = ObjectSetDescriptor {
            namespace: "ovf".into(),
            kind: "order".into(),
            ..ObjectSetDescriptor::default()
        };
        let cache: Mutex<Option<CachedObjectLogStore>> = Mutex::new(None);
        let err = compare_sql_to_log_with_cache(
            &cache,
            &log,
            &descriptor,
            &[],
            &fixture_agg("avg", "amount"),
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Evaluate(message) if message.contains("Overflow"))
        );
        let err = compare_sql_to_log_with_cache(
            &cache,
            &log,
            &descriptor,
            &[],
            &fixture_agg("min", "amount"),
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("overflow"))
        );
        compare_sql_to_log_with_cache(
            &cache,
            &log,
            &descriptor,
            &[],
            &fixture_agg("sum", "amount"),
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap();
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
            namespace: "sales".into(),
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
            namespace: "sales".into(),
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

                namespace: "sales".into(),
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

                schema_version: 1,
            }],
        )
        .unwrap();
        let visible = store.load("sales", "Customer", "c1", &acl).unwrap();
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

            namespace: "sales".into(),
            kind: kind.into(),
            key: key.into(),
            hidden: false,
            props: props
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),

            schema_version: 1,
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
                .load("sales", "Customer", "c1", &acl)
                .unwrap()
                .props
                .contains_key("secret")
        );
        drop(store);
        let descriptor = ObjectSetDescriptor {
            namespace: "sales".into(),
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
        release_object_log_cache(&cache);
        let mut store = Store::open(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![record(
                "Shipment",
                "s2",
                &[("order_id", "o1"), ("amount", "5")],
            )],
        )
        .unwrap();
        drop(store);
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

    #[test]
    fn projection_namespace_fails_closed_on_unknown_and_colliding_identities() {
        let rows = vec![
            ("sales".into(), "Customer".into(), "c1".into()),
            ("ops".into(), "Customer".into(), "c1".into()),
            ("sales".into(), "Order".into(), "o1".into()),
        ];
        assert_eq!(
            projection_namespace_for(&rows, "Order", "o1").unwrap(),
            "sales"
        );
        let unknown = projection_namespace_for(&rows, "Customer", "missing").unwrap_err();
        assert!(unknown.contains("unknown"), "{unknown}");
        let clash = projection_namespace_for(&rows, "Customer", "c1").unwrap_err();
        assert!(clash.contains("more than one namespace"), "{clash}");
    }

    #[test]
    fn two_namespaces_keep_separate_generations_for_the_same_kind_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let sales = crate::domain::Object {
            id: "shared".into(),
            kind: "Customer".into(),
            name: "Sales".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: HashMap::from([("region".into(), "eu".into())]),
            created: 1,
            updated: 1,
        };
        let ops = crate::domain::Object {
            id: "shared".into(),
            kind: "Customer".into(),
            name: "Ops".into(),
            namespace: "ops".into(),
            external_id: String::new(),
            properties: HashMap::from([("region".into(), "us".into())]),
            created: 1,
            updated: 1,
        };
        assert_eq!(apply_admitted_object_to_log(&log, &sales).unwrap(), 1);
        assert_eq!(apply_admitted_object_to_log(&log, &ops).unwrap(), 1);
        assert_eq!(apply_admitted_object_to_log(&log, &sales).unwrap(), 2);
        with_cached_object_log_store(&log, |store| {
            assert_eq!(
                identity_generation(store, "sales", "Customer", "shared").unwrap(),
                2
            );
            assert_eq!(
                identity_generation(store, "ops", "Customer", "shared").unwrap(),
                1
            );
            Ok(())
        })
        .unwrap();
        release_process_object_log_cache();
        let reopened = Store::open(&log).unwrap();
        assert_eq!(
            identity_generation(&reopened, "sales", "Customer", "shared").unwrap(),
            2
        );
        assert_eq!(
            identity_generation(&reopened, "ops", "Customer", "shared").unwrap(),
            1
        );
    }

    #[test]
    fn a_pre_namespace_log_fails_closed_naming_the_migration() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("legacy.mikura");
        std::fs::write(&log, include_bytes!("mikurav1_superblock.bin")).unwrap();
        let error = Store::open(&log).err().expect("V1 open must fail closed");
        assert!(error.contains("migrate_unnamespaced"), "{error}");
    }

    #[test]
    fn projection_migration_answers_generations_and_dual_read() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("legacy.mikura");
        let dst = dir.path().join("objects.mikura");
        std::fs::write(&src, include_bytes!("mikurav1_records.bin")).unwrap();
        let src_bytes = std::fs::read(&src).unwrap();
        let rows = vec![
            ("sales".into(), "Customer".into(), "c1".into()),
            ("sales".into(), "Order".into(), "o1".into()),
            ("sales".into(), "Shipment".into(), "s1".into()),
        ];
        assert_eq!(
            migrate_unnamespaced_object_log_from_projection(&src, &dst, &rows).unwrap(),
            3
        );
        assert_eq!(std::fs::read(&src).unwrap(), src_bytes);
        let store = Store::open(&dst).unwrap();
        assert_eq!(
            identity_generation(&store, "sales", "Customer", "c1").unwrap(),
            1
        );
        drop(store);

        let descriptor = ObjectSetDescriptor {
            namespace: "sales".into(),
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
        compare_sql_to_log_with_cache(
            &cache,
            &dst,
            &descriptor,
            &hops,
            &aggregation,
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap();
        let unknown = migrate_unnamespaced_object_log_from_projection(
            &src,
            &dir.path().join("empty.mikura"),
            &[("sales".into(), "Customer".into(), "c1".into())],
        )
        .unwrap_err();
        assert!(unknown.contains("unknown"), "{unknown}");
    }
}
