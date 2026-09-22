//! Fail-closed dual-read of EvaluateObjectSet against a tagged object-log library.
//!
//! `SEKAI_OBJECT_INDEX_DUAL_READ` compares SQL hop engines. This gate compares
//! the SQL projection to in-process mikura `ObjectSet::evaluate` (ADR 0081).

use crate::domain::Object;
use crate::sekai::object_security::ObjectSecurityPolicy;
use crate::sekai::object_set::{ObjectSetAggregation, ObjectSetDescriptor};
use crate::sekai::object_type_index::ObjectTypeIndexMember;
use mikura::{
    Aggregate, BatchIngest, EvaluateRequest, EvaluateResponse, Hop, LocalCompute, ObjectRecord,
    ObjectSet, PropertyAcl, Store,
};
use std::collections::HashSet;
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
/// different log. Safe to keep reusing otherwise: [`ensure_admitted_object_in_configured_log`]
/// and [`apply_admitted_object_to_log`] are the only production writers of
/// a configured object-log path (nothing else in this process, or any
/// other process, appends to it), so this handle's in-memory state can
/// never go stale relative to the file it wraps. That single-writer
/// funnel is exactly what a read-only comparator against a log an
/// *external* writer also appends to would not have, which is why the
/// same "keep the handle" approach is not safe for the dual-read canary
/// path (#1110).
static OBJECT_LOG_STORE: OnceLock<Mutex<Option<CachedObjectLogStore>>> = OnceLock::new();

struct CachedObjectLogStore {
    path: PathBuf,
    store: Store,
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
        Some(cached) => cached.path != path,
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
        });
    }
    let cached = guard.as_mut().expect("cache populated above");
    let result = body(&mut cached.store);
    if result.is_err() {
        *guard = None;
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
        let enabled = env::var(DUAL_READ_ENV).unwrap_or_default() == "1";
        let sample_n = env::var(SAMPLE_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(if enabled { DEFAULT_SAMPLE_N } else { 1 });
        Self {
            enabled,
            log_path: env::var(LOG_PATH_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
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
/// unexpressible grammar before any policy fetch. Store open stays inside
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
                "object-log dual-read requires SEKAI_OBJECT_LOG to an existing mikura log".into()
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
            })
            .collect(),
        sum_kind,
        sum_property,
        aggregate: Aggregate::CountAndSum,
        acl,
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

/// Project clerk property grants into the tagged deny-list.
///
/// The tagged `PropertyAcl` public API is allow-all or a single deny. A
/// non-empty grant allow-list therefore cannot be witnessed without a false
/// allow-all compare. Callers skip the canary and keep the SQL answer.
pub fn project_object_log_acl<'a>(
    policies: impl IntoIterator<Item = Option<&'a ObjectSecurityPolicy>>,
) -> Result<PropertyAcl, ObjectLogCompareError> {
    for policy in policies.into_iter().flatten() {
        if policy
            .property_grants
            .as_ref()
            .is_some_and(|grants| !grants.is_empty())
        {
            return Err(ObjectLogCompareError::GrantNarrowed);
        }
    }
    Ok(PropertyAcl::allow_all())
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
    if !path.exists() {
        return Err(ObjectLogCompareError::MissingLog);
    }
    let request = map_evaluate_request(descriptor, hops, aggregation, acl)?;
    let store = Store::open(path).map_err(ObjectLogCompareError::Evaluate)?;
    let log = ObjectSet::new(LocalCompute)
        .evaluate(&store, &request)
        .map_err(|error| ObjectLogCompareError::Evaluate(format!("{error:?}")))?;
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
pub fn ensure_admitted_object_in_configured_log(object: &Object) -> Result<Option<u64>, String> {
    let path = configured_log_path();
    let Some(path) = path else {
        return Ok(None);
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
        let existing = with_cached_object_log_store(&path, |store| {
            Ok(store
                .visible_of_kind(&object.kind)
                .into_iter()
                .find(|record| record.key == object.id)
                .filter(|record| record.props == object.properties && !record.hidden)
                .map(|record| record.r#gen))
        });
        if let Ok(Some(generation)) = existing {
            return Ok(Some(generation));
        }
    }
    apply_admitted_object_to_log(&path, object).map(Some)
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

pub fn apply_admitted_object_to_log(path: &Path, object: &Object) -> Result<u64, String> {
    with_cached_object_log_store(path, |store| {
        BatchIngest::run(store, vec![object_record(object)])?;
        identity_generation(store, &object.kind, &object.id)
    })
}

fn object_record(object: &Object) -> ObjectRecord {
    ObjectRecord {
        r#gen: 0,
        kind: object.kind.clone(),
        key: object.id.clone(),
        hidden: false,
        props: object.properties.clone(),
    }
}

pub fn identity_generation(store: &Store, kind: &str, key: &str) -> Result<u64, String> {
    store
        .visible_of_kind(kind)
        .into_iter()
        .find(|record| record.key == key)
        .map(|record| record.r#gen)
        .ok_or_else(|| format!("mikura identity missing for {kind}:{key}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mikura::{BatchIngest, ObjectRecord};
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
    fn dual_read_matches_and_fails_closed_on_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut store = Store::create(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![
                ObjectRecord {
                    r#gen: 1,
                    kind: "Customer".into(),
                    key: "c1".into(),
                    hidden: false,
                    props: HashMap::from([("region".into(), "eu".into())]),
                },
                ObjectRecord {
                    r#gen: 1,
                    kind: "Order".into(),
                    key: "o1".into(),
                    hidden: false,
                    props: HashMap::from([("customer_id".into(), "c1".into())]),
                },
                ObjectRecord {
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
        compare_sql_to_log_path(
            &log,
            &descriptor,
            &hops,
            &aggregation,
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap();

        BatchIngest::run(
            &mut store,
            vec![ObjectRecord {
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
        let err = compare_sql_to_log_path(
            &log,
            &descriptor,
            &hops,
            &aggregation,
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::Mismatch { .. }));
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

    #[test]
    fn project_object_log_acl_skips_when_grants_narrow() {
        project_object_log_acl([None]).unwrap();
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(vec![crate::sekai::object_security::PropertyGrant {
                property: "region".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }]),
            value_instance_grants: None,
            required_purpose: None,
        };
        let err = project_object_log_acl([Some(&policy)]).unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::GrantNarrowed));
    }
}
