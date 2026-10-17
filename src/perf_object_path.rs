//! Object-path control-plane workloads for GetObject, ListObjects,
//! EvaluateObjectSet, Action apply, policy-checked reads, and ApplySourceBatch.
//!
//! The `control_plane` bench and focused tests share these runners so the
//! measured path is the gRPC service implementation, not a parallel copy.

use crate::chisei::budget::{BudgetTracker, PeriodType};
use crate::composition::cross_store_admission::CrossStoreAdmission;
use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::store::{ChiseiStore, SekaiStore};
use crate::domain::{Link, Object};
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{
    ApplySourceBatchRequest, CreateObjectRequest, EvaluateObjectSetRequest, GetObjectRequest,
    ListFilter, ListObjectsRequest, ObjectSetAggregation, ObjectSetCostLimit, ObjectSetDescriptor,
    ObjectSetTraversal, PropertyFilter, SourceBatch, SourceRecord, SubmitActionInstanceRequest,
    UpdateObjectRequest,
};
use crate::grpc::sekai_service::SekaiServiceImpl;
use crate::sekai::definition_branch::{
    DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
};
use crate::sekai::governed_action_type::GovernedActionType;
use crate::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
    ObjectSecurityPredicate, ObjectSecurityRule,
};
use crate::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION, SOURCE_GITHUB,
    SourceBatch as DomainBatch, SourceRecord as DomainRecord,
};
use crate::sekai::object_type_index::{ObjectTypeDatasource, ObjectTypeIndexEdit};
use crate::sekai::schema::ObjectType;
use crate::sekai::security::{Grant, Role};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tonic::Request;
use tonic::metadata::MetadataValue;

const READER: &str = "local";
const PRODUCER: &str = "connector/github-primary";
const ACTION_TYPE: &str = "review.intake";
const PAGE_SIZE: i32 = 50;

/// Published GetObject p99 budget in microseconds (5 ms).
pub const GET_OBJECT_P99_US: f64 = 5_000.0;
/// Published list-page p95 budget in microseconds (25 ms at 10⁵).
pub const LIST_PAGE_P95_US: f64 = 25_000.0;
/// Published Action apply p99 budget in microseconds (25 ms).
pub const ACTION_APPLY_P99_US: f64 = 25_000.0;
/// Policy-checked read may cost at most this fraction more than unrestricted.
pub const POLICY_OVERHEAD_FRACTION: f64 = 0.20;
/// Published ApplySourceBatch throughput floor.
pub const APPLY_SOURCE_BATCH_MIN_RECORDS_PER_SEC: f64 = 2_000.0;

/// Kind of object-path operation encoded in a workload id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectPathKind {
    GetObject,
    ListPage,
    EvaluateFilter,
    EvaluateSort,
    EvaluateOneHop,
    EvaluateTwoHop,
    ActionApply,
    PolicyCheckedRead,
    CreateObject,
    UpdateObject,
    ApplySourceBatch,
}

/// Persistence backend encoded in a workload id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectPathBackend {
    Sqlite,
    Postgres,
}

/// Scale token encoded in a workload id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectPathScale {
    TenK,
    HundredK,
    Batch100,
    Batch1000,
    Smoke,
}

/// Parsed object-path workload identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectPathId {
    pub kind: ObjectPathKind,
    pub backend: ObjectPathBackend,
    pub scale: ObjectPathScale,
}

/// Parse `{kind}_{sqlite|postgres}_{10k|100k|100|1000|smoke}`.
pub fn parse_workload_id(id: &str) -> Option<ObjectPathId> {
    let (rest, scale) = id
        .strip_suffix("_100k")
        .map(|rest| (rest, ObjectPathScale::HundredK))
        .or_else(|| {
            id.strip_suffix("_10k")
                .map(|rest| (rest, ObjectPathScale::TenK))
        })
        .or_else(|| {
            id.strip_suffix("_1000")
                .map(|rest| (rest, ObjectPathScale::Batch1000))
        })
        .or_else(|| {
            id.strip_suffix("_100")
                .map(|rest| (rest, ObjectPathScale::Batch100))
        })
        .or_else(|| {
            id.strip_suffix("_smoke")
                .map(|rest| (rest, ObjectPathScale::Smoke))
        })?;
    let (kind, backend) = rest
        .strip_suffix("_sqlite")
        .map(|kind| (kind, ObjectPathBackend::Sqlite))
        .or_else(|| {
            rest.strip_suffix("_postgres")
                .map(|kind| (kind, ObjectPathBackend::Postgres))
        })?;
    let kind = match kind {
        "get_object" => ObjectPathKind::GetObject,
        "list_page" => ObjectPathKind::ListPage,
        "evaluate_object_set_filter" => ObjectPathKind::EvaluateFilter,
        "evaluate_object_set_sort" => ObjectPathKind::EvaluateSort,
        "evaluate_object_set_one_hop" => ObjectPathKind::EvaluateOneHop,
        "evaluate_object_set_two_hop" => ObjectPathKind::EvaluateTwoHop,
        "action_apply" => ObjectPathKind::ActionApply,
        "policy_checked_read" => ObjectPathKind::PolicyCheckedRead,
        "create_object" => ObjectPathKind::CreateObject,
        "update_object" => ObjectPathKind::UpdateObject,
        "apply_source_batch_grpc" => ObjectPathKind::ApplySourceBatch,
        _ => return None,
    };
    Some(ObjectPathId {
        kind,
        backend,
        scale,
    })
}

/// True when this workload can run in the current process environment.
pub fn postgres_url_configured() -> bool {
    env::var("SEKAI_BENCH_POSTGRES_URL")
        .ok()
        .or_else(|| env::var("SEKAI_TEST_POSTGRES_URL").ok())
        .is_some_and(|value| !value.trim().is_empty())
}

/// Repeating object-path sample used by the control-plane bench.
pub type ObjectPathBenchmark = Box<dyn FnMut() -> Result<(), String>>;

/// Build a repeating object-path benchmark, or `None` when `id` is not one.
pub fn benchmark_for(
    id: &str,
    dataset_size: usize,
    operations_per_iteration: usize,
) -> Result<Option<ObjectPathBenchmark>, String> {
    let Some(parsed) = parse_workload_id(id) else {
        return Ok(None);
    };
    if parsed.backend == ObjectPathBackend::Postgres && !postgres_url_configured() {
        return Err(
            "postgres object-path workloads require SEKAI_BENCH_POSTGRES_URL or SEKAI_TEST_POSTGRES_URL"
                .into(),
        );
    }
    let harness = ObjectPathHarness::cached(parsed, dataset_size, operations_per_iteration)?;
    Ok(Some(Box::new(move || harness.run_once())))
}

/// Shared seeded graph. Read workloads reuse one fixture per (backend, size).
struct ObjectPathInner {
    runtime: tokio::runtime::Runtime,
    service: Arc<SekaiServiceImpl>,
    namespace: String,
    target_id: String,
    definition_digest: String,
    dataset_size: usize,
    _sqlite_dir: Option<ScratchDir>,
}

/// In-process gRPC object-path fixture used by the bench and tests.
pub struct ObjectPathHarness {
    inner: Arc<ObjectPathInner>,
    parsed: ObjectPathId,
    batch_records: usize,
    sequence: AtomicU64,
}

/// File-backed SQLite directory owned by the harness for the process lifetime.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn create() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = env::temp_dir().join(format!(
            "sekai-object-path-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)
            .map_err(|error| format!("create object-path directory: {error}"))?;
        Ok(Self { path })
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum GraphFlavor {
    Read,
    Policy,
    Action,
    Write,
    Batch,
    TwoHop,
}

fn flavor(kind: ObjectPathKind) -> GraphFlavor {
    match kind {
        ObjectPathKind::PolicyCheckedRead => GraphFlavor::Policy,
        ObjectPathKind::ActionApply => GraphFlavor::Action,
        ObjectPathKind::CreateObject | ObjectPathKind::UpdateObject => GraphFlavor::Write,
        ObjectPathKind::ApplySourceBatch => GraphFlavor::Batch,
        ObjectPathKind::EvaluateTwoHop => GraphFlavor::TwoHop,
        _ => GraphFlavor::Read,
    }
}

type CachedGraph = (ObjectPathBackend, usize, GraphFlavor, Arc<ObjectPathInner>);

fn graph_cache() -> &'static Mutex<Vec<CachedGraph>> {
    static CACHE: OnceLock<Mutex<Vec<CachedGraph>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Drop cached graphs whose harnesses are gone so SQLite dirs are removed.
pub fn release_cached_graphs() {
    if let Ok(mut cache) = graph_cache().lock() {
        cache.retain(|(_, _, _, inner)| Arc::strong_count(inner) > 1);
    }
}

impl ObjectPathHarness {
    /// Reuse a seeded graph for read-mostly workloads in one bench process.
    pub fn cached(
        parsed: ObjectPathId,
        dataset_size: usize,
        operations_per_iteration: usize,
    ) -> Result<Arc<Self>, String> {
        let flavor = flavor(parsed.kind);
        if matches!(
            flavor,
            GraphFlavor::Write | GraphFlavor::Batch | GraphFlavor::Action
        ) {
            return Ok(Arc::new(Self::open(
                parsed,
                dataset_size,
                operations_per_iteration,
            )?));
        }
        let mut cache = graph_cache()
            .lock()
            .map_err(|_| "object-path graph cache poisoned".to_string())?;
        if let Some((_, _, _, inner)) = cache.iter().find(|(backend, size, cached_flavor, _)| {
            *backend == parsed.backend && *size == dataset_size && *cached_flavor == flavor
        }) {
            return Ok(Arc::new(Self::from_inner(
                Arc::clone(inner),
                parsed,
                operations_per_iteration,
            )));
        }
        let harness = Self::open(parsed, dataset_size, operations_per_iteration)?;
        cache.push((
            parsed.backend,
            dataset_size,
            flavor,
            Arc::clone(&harness.inner),
        ));
        Ok(Arc::new(harness))
    }

    fn from_inner(
        inner: Arc<ObjectPathInner>,
        parsed: ObjectPathId,
        operations_per_iteration: usize,
    ) -> Self {
        let batch_records = match parsed.kind {
            ObjectPathKind::ApplySourceBatch => operations_per_iteration.max(1),
            _ => 0,
        };
        Self {
            inner,
            parsed,
            batch_records,
            sequence: AtomicU64::new(1),
        }
    }

    /// Kind this harness measures. Cached graphs keep the requested operation.
    pub fn kind(&self) -> ObjectPathKind {
        self.parsed.kind
    }

    /// Open a file-backed SQLite or PostgreSQL store and seed the graph.
    pub fn open(
        parsed: ObjectPathId,
        dataset_size: usize,
        operations_per_iteration: usize,
    ) -> Result<Self, String> {
        if dataset_size == 0 {
            return Err("object-path dataset_size must be positive".into());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| format!("object-path runtime: {error}"))?;
        static NEXT_NS: AtomicU64 = AtomicU64::new(1);
        let unique = format!(
            "op-{}-{}",
            std::process::id(),
            NEXT_NS.fetch_add(1, Ordering::Relaxed)
        );
        let (store, sqlite_dir) = match parsed.backend {
            ObjectPathBackend::Sqlite => {
                let directory = ScratchDir::create()?;
                let path = directory.path.join("sekai.db");
                let path = path.to_str().ok_or("object-path path is not UTF-8")?;
                let db = RuntimeDb::Sqlite(Arc::new(crate::db::sekai::SekaiDb::new(path)?));
                (
                    SekaiStore::from_shared_runtime(Arc::new(db)),
                    Some(directory),
                )
            }
            ObjectPathBackend::Postgres => {
                let db = open_postgres()?;
                (SekaiStore::from_shared_runtime(db), None)
            }
        };
        let namespace = format!("object-path-{unique}");
        seed_namespace(store.runtime(), &namespace)?;
        let digest = seed_definition(store.runtime(), &namespace)?;
        seed_graph(store.runtime(), &namespace, dataset_size)?;
        if parsed.kind == ObjectPathKind::EvaluateTwoHop {
            seed_two_hop_index(store.runtime(), &namespace, &digest, dataset_size)?;
        }
        if parsed.kind == ObjectPathKind::PolicyCheckedRead {
            activate_visibility_policy(store.runtime(), &namespace)?;
        }
        if parsed.kind == ObjectPathKind::ActionApply {
            seed_action_type(store.runtime(), &namespace)?;
        }
        let chisei = ChiseiStore::from_shared_runtime(store.runtime_arc());
        let budget = Arc::new(BudgetTracker::new(chisei.clone()));
        budget.set_limit("action:governed", 1_000_000_000, PeriodType::Daily)?;
        let clerk = Arc::new(CrossStoreAdmission::new(
            chisei,
            store.clone(),
            Some(budget),
        ));
        let service = Arc::new(SekaiServiceImpl::new(store).with_cross_store_admission(clerk));
        Ok(Self::from_inner(
            Arc::new(ObjectPathInner {
                runtime,
                service,
                target_id: graph_id(&namespace, "item", 0),
                namespace,
                definition_digest: digest,
                dataset_size,
                _sqlite_dir: sqlite_dir,
            }),
            parsed,
            operations_per_iteration,
        ))
    }

    /// Run one sample of the selected operation through the gRPC handler.
    pub fn run_once(&self) -> Result<(), String> {
        match self.parsed.kind {
            ObjectPathKind::GetObject | ObjectPathKind::PolicyCheckedRead => self.get_object(),
            ObjectPathKind::ListPage => self.list_page(),
            ObjectPathKind::EvaluateFilter => self.evaluate(EvaluateMode::Filter),
            ObjectPathKind::EvaluateSort => self.evaluate(EvaluateMode::Sort),
            ObjectPathKind::EvaluateOneHop => self.evaluate(EvaluateMode::OneHop),
            ObjectPathKind::EvaluateTwoHop => self.evaluate(EvaluateMode::TwoHop),
            ObjectPathKind::ActionApply => self.action_apply(),
            ObjectPathKind::CreateObject => self.create_object(),
            ObjectPathKind::UpdateObject => self.update_object(),
            ObjectPathKind::ApplySourceBatch => self.apply_source_batch(),
        }
    }

    /// SQLite fixture directory, when this harness is file-backed.
    pub fn sqlite_dir_path(&self) -> Option<&Path> {
        self.inner
            ._sqlite_dir
            .as_ref()
            .map(|dir| dir.path.as_path())
    }

    /// Properties of the seeded target object through GetObject.
    pub fn target_properties(&self) -> Result<HashMap<String, String>, String> {
        Ok(self.fetch_target()?.properties)
    }

    fn fetch_target(&self) -> Result<crate::grpc::pb::sekai::Object, String> {
        let response = self.block_on(self.inner.service.get_object(with_principal(
            GetObjectRequest {
                id: self.inner.target_id.clone(),
            },
            READER,
        )))?;
        let object = response
            .into_inner()
            .object
            .ok_or("GetObject returned no object")?;
        if object.id != self.inner.target_id {
            return Err("GetObject returned a different object".into());
        }
        Ok(object)
    }

    /// Point-read the seeded target object.
    pub fn get_object(&self) -> Result<(), String> {
        self.fetch_target().map(|_| ())
    }

    /// List one page of 50 items in the seeded namespace.
    pub fn list_page(&self) -> Result<(), String> {
        let response = self.block_on(self.inner.service.list_objects(with_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "Item".into(),
                    namespace: self.inner.namespace.clone(),
                    limit: PAGE_SIZE,
                    ..Default::default()
                }),
                page_token: String::new(),
            },
            READER,
        )))?;
        let inner = response.into_inner();
        if inner.objects.is_empty() {
            return Err("ListObjects returned an empty page".into());
        }
        if inner.objects.len() > PAGE_SIZE as usize {
            return Err("ListObjects exceeded the page size".into());
        }
        Ok(())
    }

    fn evaluate(&self, mode: EvaluateMode) -> Result<(), String> {
        let descriptor = match mode {
            EvaluateMode::Filter => ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
                namespace: self.inner.namespace.clone(),
                kind: "Item".into(),
                definition_digest: self.inner.definition_digest.clone(),
                property_filters: vec![PropertyFilter {
                    key: "region".into(),
                    op: "eq".into(),
                    value: "eu".into(),
                }],
                order_by: String::new(),
                descending: false,
                limit: PAGE_SIZE,
                cost_limit: None,
                ..Default::default()
            },
            EvaluateMode::Sort => ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
                namespace: self.inner.namespace.clone(),
                kind: "Item".into(),
                definition_digest: self.inner.definition_digest.clone(),
                property_filters: vec![],
                order_by: "property:rank".into(),
                descending: true,
                limit: PAGE_SIZE,
                cost_limit: None,
                ..Default::default()
            },
            EvaluateMode::OneHop => ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
                namespace: self.inner.namespace.clone(),
                kind: "Item".into(),
                definition_digest: self.inner.definition_digest.clone(),
                property_filters: vec![],
                order_by: String::new(),
                descending: false,
                limit: PAGE_SIZE,
                traversal: Some(ObjectSetTraversal {
                    relation: "placed".into(),
                    direction: "outgoing".into(),
                    far_kind: "Order".into(),
                    join_property: String::new(),
                }),
                cost_limit: None,
                ..Default::default()
            },
            EvaluateMode::TwoHop => ObjectSetDescriptor {
                contract_version: crate::sekai::object_set::CONTRACT_VERSION_V2.into(),
                namespace: self.inner.namespace.clone(),
                kind: "Item".into(),
                definition_digest: self.inner.definition_digest.clone(),
                hops: vec![
                    ObjectSetTraversal {
                        relation: "placed".into(),
                        direction: "outgoing".into(),
                        far_kind: "Order".into(),
                        join_property: "item_id".into(),
                    },
                    ObjectSetTraversal {
                        relation: "ships".into(),
                        direction: "outgoing".into(),
                        far_kind: "Shipment".into(),
                        join_property: "order_id".into(),
                    },
                ],
                aggregation: Some(ObjectSetAggregation {
                    function: "count".into(),
                    property: String::new(),
                    group_by: "region".into(),
                }),
                limit: PAGE_SIZE,
                cost_limit: Some(scan_limit(self.inner.dataset_size)),
                ..Default::default()
            },
        };
        let response = self.block_on(self.inner.service.evaluate_object_set(with_principal(
            EvaluateObjectSetRequest {
                descriptor: Some(descriptor),
                page_token: String::new(),
                required_freshness_ms: 0,
            },
            READER,
        )))?;
        let inner = response.into_inner();
        if inner.members.is_empty() && inner.aggregates.is_empty() {
            return Err("EvaluateObjectSet returned no members".into());
        }
        Ok(())
    }

    /// Submit one governed Action instance that updates the seeded Item.
    pub fn action_apply(&self) -> Result<(), String> {
        let step = self.sequence.fetch_add(1, Ordering::Relaxed);
        let response = self.block_on(self.inner.service.submit_action_instance(with_principal(
            SubmitActionInstanceRequest {
                namespace: self.inner.namespace.clone(),
                type_id: ACTION_TYPE.into(),
                version: "1.0.0".into(),
                parameters_json: format!(
                    r#"{{"object_id":"{}","rank":{}}}"#,
                    self.inner.target_id,
                    10_000 + step
                ),
                idempotency_key: format!("idem-{step}"),
                evidence_submission_ids: vec![],
                request_id: format!("req-{step}"),
                ontology_digest: String::new(),
            },
            READER,
        )))?;
        let inner = response.into_inner();
        if inner.instance.is_none() {
            return Err("SubmitActionInstance returned no instance".into());
        }
        Ok(())
    }

    /// Create one additional object through the gRPC handler.
    pub fn create_object(&self) -> Result<(), String> {
        let step = self.sequence.fetch_add(1, Ordering::Relaxed);
        let id = format!("{}-created-{step}", self.inner.namespace);
        let response = self.block_on(self.inner.service.create_object(with_principal(
            CreateObjectRequest {
                object: Some(proto_item(&self.inner.namespace, &id, 0)),
                lease_precondition: None,
            },
            READER,
        )))?;
        if response.into_inner().object.is_none() {
            return Err("CreateObject returned no object".into());
        }
        Ok(())
    }

    /// Update the seeded target object's name through the gRPC handler.
    pub fn update_object(&self) -> Result<(), String> {
        let step = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut object = proto_item(&self.inner.namespace, &self.inner.target_id, 0);
        object.name = format!("updated-{step}");
        let response = self.block_on(self.inner.service.update_object(with_principal(
            UpdateObjectRequest {
                object: Some(object),
                lease_precondition: None,
            },
            READER,
        )))?;
        if response.into_inner().object.is_none() {
            return Err("UpdateObject returned no object".into());
        }
        Ok(())
    }

    /// Apply one source batch through the gRPC handler.
    pub fn apply_source_batch(&self) -> Result<(), String> {
        let step = self.sequence.fetch_add(1, Ordering::Relaxed);
        let current = if step <= 1 {
            String::new()
        } else {
            format!("cursor:{}", step - 1)
        };
        let batch = source_batch_proto(
            &self.inner.namespace,
            &current,
            &format!("cursor:{step}"),
            &format!("batch-{step}"),
            self.batch_records.max(1),
            step,
        )?;
        let response = self.block_on(self.inner.service.apply_source_batch(with_principal(
            ApplySourceBatchRequest { batch: Some(batch) },
            PRODUCER,
        )))?;
        let result = response
            .into_inner()
            .result
            .ok_or("ApplySourceBatch returned no result")?;
        let status = result
            .transaction
            .as_ref()
            .map(|transaction| transaction.status.as_str())
            .unwrap_or_default();
        if status != "COMMITTED" {
            let reason = result
                .transaction
                .as_ref()
                .map(|transaction| transaction.reason.clone())
                .unwrap_or_default();
            return Err(format!("ApplySourceBatch status {status}: {reason}"));
        }
        Ok(())
    }

    fn block_on<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, tonic::Status>>,
    ) -> Result<T, String> {
        self.inner
            .runtime
            .block_on(future)
            .map_err(|status| format!("{status}"))
    }
}

#[derive(Clone, Copy)]
enum EvaluateMode {
    Filter,
    Sort,
    OneHop,
    TwoHop,
}

fn scan_limit(dataset_size: usize) -> ObjectSetCostLimit {
    ObjectSetCostLimit {
        max_rows_scanned: (dataset_size as i32).saturating_mul(8).max(10_000),
        max_depth: 3,
        max_time_ms: 0,
    }
}

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).expect("principal is valid metadata"),
    );
    req
}

fn open_postgres() -> Result<Arc<RuntimeDb>, String> {
    let url = env::var("SEKAI_BENCH_POSTGRES_URL")
        .or_else(|_| env::var("SEKAI_TEST_POSTGRES_URL"))
        .map_err(|_| {
            "postgres object-path workloads require SEKAI_BENCH_POSTGRES_URL".to_string()
        })?;
    let ca_path = env::var("SEKAI_POSTGRES_CA_CERT")
        .ok()
        .or_else(|| env::var("SEKAI_TEST_POSTGRES_CA_CERT").ok());
    let db = match ca_path {
        Some(path) if !path.trim().is_empty() => {
            let pem = std::fs::read(&path).map_err(|error| format!("read postgres CA: {error}"))?;
            PostgresDb::connect_with_ca_certificate(&url, 8, &pem)?
        }
        _ => PostgresDb::connect(&url, 8)?,
    };
    Ok(Arc::new(RuntimeDb::Postgres(Arc::new(db))))
}

fn seed_namespace(db: &RuntimeDb, namespace: &str) -> Result<(), String> {
    db.ensure_team_namespace(namespace, READER, Role::Admin, READER)?;
    db.ensure_team_namespace(namespace, PRODUCER, Role::Editor, READER)?;
    db.create_grant(&Grant {
        id: format!("action-admin-{namespace}"),
        object_id: "action".into(),
        principal: READER.into(),
        role: Role::Admin,
        created: 1,
    })?;
    Ok(())
}

fn seed_definition(db: &RuntimeDb, namespace: &str) -> Result<String, String> {
    let members = vec![
        member(
            namespace,
            "object_type",
            "Item",
            r#"{"name":"Item","properties":{"region":{"type":"string"},"rank":{"type":"integer"},"visibility":{"type":"string"}}}"#,
        )?,
        member(
            namespace,
            "object_type",
            "Order",
            r#"{"name":"Order","properties":{"status":{"type":"string"}}}"#,
        )?,
        member(
            namespace,
            "object_type",
            "Shipment",
            r#"{"name":"Shipment","properties":{"status":{"type":"string"}}}"#,
        )?,
        member(
            namespace,
            "link_type",
            "placed",
            r#"{"name":"placed","from":"Item","to":"Order"}"#,
        )?,
        member(
            namespace,
            "link_type",
            "ships",
            r#"{"name":"ships","from":"Order","to":"Shipment"}"#,
        )?,
    ];
    let revision = prepare_revision(
        namespace,
        "",
        members.iter().map(|item| DefinitionRevisionMember {
            member_kind: item.member_kind.clone(),
            member_id: item.member_id.clone(),
            member_digest: item.member_digest.clone(),
        }),
        true,
        "root",
        1,
    )?;
    db.seed_published_definition_revision(&revision, &members)?;
    Ok(revision.revision_digest)
}

fn member(
    namespace: &str,
    kind: &str,
    id: &str,
    json: &str,
) -> Result<crate::sekai::definition_branch::DefinitionMember, String> {
    DefinitionMemberInput {
        member_kind: kind.into(),
        member_id: id.into(),
        definition_json: json.into(),
        member_digest: String::new(),
    }
    .prepare(namespace)
}

fn graph_id(namespace: &str, stem: &str, index: usize) -> String {
    format!("{namespace}-{stem}-{index}")
}

fn seed_two_hop_index(
    db: &RuntimeDb,
    namespace: &str,
    digest: &str,
    dataset_size: usize,
) -> Result<(), String> {
    for kind in ["Item", "Order", "Shipment"] {
        let property_mapping = match kind {
            "Item" => BTreeMap::from([("region".into(), "region".into())]),
            "Order" => BTreeMap::from([("item_id".into(), "item_id".into())]),
            "Shipment" => BTreeMap::from([("order_id".into(), "order_id".into())]),
            _ => BTreeMap::new(),
        };
        let binding = ObjectTypeDatasource {
            contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            kind: kind.into(),
            definition_digest: digest.into(),
            dataset_id: String::new(),
            key_column: String::new(),
            property_mapping,
            hidden_column: String::new(),
            edits_only: true,
        }
        .prepare()
        .map_err(|error| error.message())?;
        db.register_object_type_datasource(&binding, 30)?;
        for index in 0..dataset_size {
            let (source_key, properties) = match kind {
                "Item" => (
                    graph_id(namespace, "item", index),
                    BTreeMap::from([(
                        "region".into(),
                        if index.is_multiple_of(2) { "eu" } else { "us" }.into(),
                    )]),
                ),
                "Order" => (
                    graph_id(namespace, "order", index),
                    BTreeMap::from([("item_id".into(), graph_id(namespace, "item", index))]),
                ),
                "Shipment" => (
                    graph_id(namespace, "shipment", index),
                    BTreeMap::from([("order_id".into(), graph_id(namespace, "order", index))]),
                ),
                _ => continue,
            };
            db.put_object_type_index_edit(&ObjectTypeIndexEdit {
                namespace: namespace.into(),
                kind: kind.into(),
                source_key,
                properties,
                hidden: false,
            })?;
        }
        db.apply_object_type_index(namespace, kind, true, 40)?;
    }
    Ok(())
}

fn seed_graph(db: &RuntimeDb, namespace: &str, dataset_size: usize) -> Result<(), String> {
    for index in 0..dataset_size {
        db.create_object(&item_object(namespace, index))?;
        db.create_object(&order_object(namespace, index))?;
        db.create_object(&shipment_object(namespace, index))?;
        db.create_link(&Link {
            id: graph_id(namespace, "placed", index),
            from_id: graph_id(namespace, "item", index),
            to_id: graph_id(namespace, "order", index),
            relation: "placed".into(),
            created: index as i64,
        })?;
        db.create_link(&Link {
            id: graph_id(namespace, "ships", index),
            from_id: graph_id(namespace, "order", index),
            to_id: graph_id(namespace, "shipment", index),
            relation: "ships".into(),
            created: index as i64,
        })?;
    }
    Ok(())
}

fn item_object(namespace: &str, index: usize) -> Object {
    Object {
        id: graph_id(namespace, "item", index),
        kind: "Item".into(),
        name: format!("Item {index}"),
        namespace: namespace.into(),
        external_id: format!("{namespace}:item:{index}"),
        properties: HashMap::from([
            (
                "region".into(),
                if index.is_multiple_of(2) { "eu" } else { "us" }.into(),
            ),
            ("rank".into(), (index % 10).to_string()),
            ("visibility".into(), "visible".into()),
        ]),
        created: index as i64,
        updated: index as i64,
    }
}

fn order_object(namespace: &str, index: usize) -> Object {
    Object {
        id: graph_id(namespace, "order", index),
        kind: "Order".into(),
        name: format!("Order {index}"),
        namespace: namespace.into(),
        external_id: format!("{namespace}:order:{index}"),
        properties: HashMap::from([("status".into(), "open".into())]),
        created: index as i64,
        updated: index as i64,
    }
}

fn shipment_object(namespace: &str, index: usize) -> Object {
    Object {
        id: graph_id(namespace, "shipment", index),
        kind: "Shipment".into(),
        name: format!("Shipment {index}"),
        namespace: namespace.into(),
        external_id: format!("{namespace}:shipment:{index}"),
        properties: HashMap::from([("status".into(), "ready".into())]),
        created: index as i64,
        updated: index as i64,
    }
}

fn proto_item(namespace: &str, id: &str, rank: usize) -> crate::grpc::pb::sekai::Object {
    crate::grpc::pb::sekai::Object {
        id: id.into(),
        kind: "Item".into(),
        name: id.into(),
        namespace: namespace.into(),
        external_id: format!("{namespace}:{id}"),
        properties: HashMap::from([
            ("region".into(), "eu".into()),
            ("rank".into(), rank.to_string()),
            ("visibility".into(), "visible".into()),
        ]),
        created: 1,
        updated: 1,
    }
}

fn activate_visibility_policy(db: &RuntimeDb, namespace: &str) -> Result<(), String> {
    let mut policies = BTreeMap::new();
    for (kind, predicates, stamp) in [
        (
            "Item",
            vec![ObjectSecurityPredicate::PropertyEquals {
                property: "visibility".into(),
                value: "visible".into(),
            }],
            10i64,
        ),
        ("Order", vec![ObjectSecurityPredicate::AllowAll], 11),
        ("Shipment", vec![ObjectSecurityPredicate::AllowAll], 12),
        ("namespace", vec![ObjectSecurityPredicate::AllowAll], 13),
    ] {
        let policy = ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: namespace.into(),
            kind: kind.into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates,
            }],
            property_grants: None,
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = db.put_object_security_policy(
            &policy,
            READER,
            &format!("put-visibility-{kind}"),
            stamp,
        )?;
        policies.insert(kind.to_string(), revision.revision_digest);
    }
    db.activate_object_security_policies(namespace, &policies, READER, "activate-visibility", 20)?;
    Ok(())
}

fn seed_action_type(db: &RuntimeDb, namespace: &str) -> Result<(), String> {
    db.upsert_object_type(&ObjectType {
        kind: "Item".into(),
        description: "object-path fixture item".into(),
        properties: vec![],
        is_builtin: false,
        implements: vec![],
    })?;
    let type_def = GovernedActionType {
        approvers: Vec::new(),
        namespace: namespace.into(),
        type_id: ACTION_TYPE.into(),
        version: "1.0.0".into(),
        description: "Admit review".into(),
        parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"rank":{"type":"integer"}},"required":["object_id"],"additionalProperties":false}"#.into(),
        allowed_effect_kinds: vec!["runtime_dispatch".into()],
        policy_scope: String::new(),
        budget_scope: String::new(),
        enabled: true,
        created_by: String::new(),
        created_at_ms: 0,
        updated_at_ms: 0,
        disabled_at_ms: 0,
        object_kind: "Item".into(),
        object_mutation: "update".into(),
        submission_criteria: vec![],
        declared_effect_kinds: vec![],
        system_one: None,
    };
    db.put_governed_action_type(type_def, READER, 1).map(|_| ())
}

fn source_batch_proto(
    namespace: &str,
    current: &str,
    next: &str,
    key: &str,
    records: usize,
    step: u64,
) -> Result<SourceBatch, String> {
    let source_instance = "acme/ops";
    let domain_records = (0..records)
        .map(|index| {
            let number = step * 10_000 + index as u64;
            DomainRecord {
                source: SOURCE_GITHUB.into(),
                source_instance: source_instance.into(),
                external_id: number.to_string(),
                source_version: format!("issue-v{step}"),
                type_name: "Issue".into(),
                display_name: format!("synthetic issue {number}"),
                payload_digest: format!("sha256:{number:064x}"),
                properties: BTreeMap::from([
                    ("state".into(), "open".into()),
                    ("visibility".into(), "visible".into()),
                ]),
                deleted: false,
                observed_at_ms: 10,
                source_sequence: None,
            }
        })
        .collect();
    let mut domain = DomainBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: namespace.into(),
        producer_identity: PRODUCER.into(),
        source: SOURCE_GITHUB.into(),
        source_instance: source_instance.into(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        current_cursor: current.into(),
        proposed_next_cursor: next.into(),
        idempotency_key: key.into(),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records: domain_records,
        delivery: None,
    };
    domain.batch_digest = domain
        .canonical_digest()
        .map_err(|error| error.to_string())?;
    Ok(SourceBatch {
        contract_version: domain.contract_version,
        namespace: domain.namespace,
        producer_identity: domain.producer_identity,
        source: domain.source,
        source_instance: domain.source_instance,
        family: domain.family,
        adapter_id: domain.adapter_id,
        adapter_version: domain.adapter_version,
        type_digest: domain.type_digest,
        current_cursor: domain.current_cursor,
        proposed_next_cursor: domain.proposed_next_cursor,
        idempotency_key: domain.idempotency_key,
        batch_digest: domain.batch_digest,
        collected_at_ms: domain.collected_at_ms,
        records: domain
            .records
            .into_iter()
            .map(|record| SourceRecord {
                source: record.source,
                source_instance: record.source_instance,
                external_id: record.external_id,
                source_version: record.source_version,
                type_name: record.type_name,
                display_name: record.display_name,
                payload_digest: record.payload_digest,
                properties: record.properties.into_iter().collect(),
                deleted: record.deleted,
                observed_at_ms: record.observed_at_ms,
                source_sequence: record.source_sequence,
            })
            .collect(),
        delivery: None,
    })
}

/// Measure policy-checked GetObject overhead against unrestricted GetObject.
pub fn policy_read_overhead_fraction(dataset_size: usize) -> Result<f64, String> {
    let unrestricted = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::GetObject,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset_size,
        1,
    )?;
    let policy = ObjectPathHarness::open(
        ObjectPathId {
            kind: ObjectPathKind::PolicyCheckedRead,
            backend: ObjectPathBackend::Sqlite,
            scale: ObjectPathScale::Smoke,
        },
        dataset_size,
        1,
    )?;
    let warmup = 8usize;
    let samples = 48usize;
    sample_mean_us(&unrestricted, warmup)?;
    sample_mean_us(&policy, warmup)?;
    let unrestricted_us = sample_mean_us(&unrestricted, samples)?;
    let policy_us = sample_mean_us(&policy, samples)?;
    if unrestricted_us <= 0.0 {
        return Err("unrestricted GetObject produced no duration".into());
    }
    Ok((policy_us / unrestricted_us) - 1.0)
}

fn sample_mean_us(harness: &ObjectPathHarness, samples: usize) -> Result<f64, String> {
    let mut total = 0.0;
    for _ in 0..samples {
        let started = Instant::now();
        harness.run_once()?;
        total += started.elapsed().as_secs_f64() * 1_000_000.0;
    }
    Ok(total / samples as f64)
}

/// Workload ids the object-path manifests must publish.
pub fn required_workload_ids() -> &'static [&'static str] {
    &[
        "get_object_sqlite_10k",
        "get_object_sqlite_100k",
        "get_object_postgres_10k",
        "get_object_postgres_100k",
        "list_page_sqlite_10k",
        "list_page_sqlite_100k",
        "list_page_postgres_10k",
        "list_page_postgres_100k",
        "evaluate_object_set_filter_sqlite_10k",
        "evaluate_object_set_filter_sqlite_100k",
        "evaluate_object_set_filter_postgres_10k",
        "evaluate_object_set_filter_postgres_100k",
        "evaluate_object_set_sort_sqlite_10k",
        "evaluate_object_set_sort_sqlite_100k",
        "evaluate_object_set_sort_postgres_10k",
        "evaluate_object_set_sort_postgres_100k",
        "evaluate_object_set_one_hop_sqlite_10k",
        "evaluate_object_set_one_hop_sqlite_100k",
        "evaluate_object_set_one_hop_postgres_10k",
        "evaluate_object_set_one_hop_postgres_100k",
        "evaluate_object_set_two_hop_sqlite_10k",
        "evaluate_object_set_two_hop_sqlite_100k",
        "evaluate_object_set_two_hop_postgres_10k",
        "evaluate_object_set_two_hop_postgres_100k",
        "action_apply_sqlite_10k",
        "action_apply_sqlite_100k",
        "action_apply_postgres_10k",
        "action_apply_postgres_100k",
        "policy_checked_read_sqlite_10k",
        "policy_checked_read_sqlite_100k",
        "policy_checked_read_postgres_10k",
        "policy_checked_read_postgres_100k",
        "create_object_sqlite_10k",
        "create_object_sqlite_100k",
        "create_object_postgres_10k",
        "create_object_postgres_100k",
        "update_object_sqlite_10k",
        "update_object_sqlite_100k",
        "update_object_postgres_10k",
        "update_object_postgres_100k",
        "apply_source_batch_grpc_sqlite_100",
        "apply_source_batch_grpc_sqlite_1000",
        "apply_source_batch_grpc_postgres_100",
        "apply_source_batch_grpc_postgres_1000",
    ]
}

/// Smoke subset ids. Wide budgets, tiny datasets.
pub fn smoke_workload_ids() -> &'static [&'static str] {
    &[
        "get_object_sqlite_smoke",
        "list_page_sqlite_smoke",
        "evaluate_object_set_filter_sqlite_smoke",
        "evaluate_object_set_sort_sqlite_smoke",
        "evaluate_object_set_one_hop_sqlite_smoke",
        "evaluate_object_set_two_hop_sqlite_smoke",
        "action_apply_sqlite_smoke",
        "policy_checked_read_sqlite_smoke",
        "apply_source_batch_grpc_sqlite_smoke",
    ]
}
