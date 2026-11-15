//! Seeded differential test of the object log against the relational
//! projection (#2293).
//!
//! A seed generates a small schema, a list of writes and, at every
//! checkpoint, a set of `EvaluateObjectSet` requests. Each write lands in
//! both engines: a dataset row the relational index projects, and a log
//! record. Every request goes through the service with the object-log
//! dual-read gate on at sample rate 1, so the gate compares both engines and
//! fails closed on a disagreement. The gate's own outcome counter tells the
//! harness whether a request was compared or skipped; a skip is counted, not
//! failed.
//!
//! A failure is cut to the shortest prefix of the writes that still fails
//! and reported with the line that reruns it:
//!
//! ```text
//! SEKAI_DIFF_SEED=4711 SEKAI_DIFF_OPS=83 cargo test --test object_log_differential
//! ```
//!
//! `SEKAI_DIFF_SEED` runs one seed; `SEKAI_DIFF_CASES` runs that many seeds
//! from it (or from 1); `SEKAI_DIFF_OPS` sets the number of writes.
//!
//! Each case uses an in-memory database and its own temporary directory and
//! binds no port, so copies of this test can run side by side.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::domain::PropertyFilter;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    EvaluateObjectSetRequest, ObjectSetAggregation, ObjectSetCostLimit, ObjectSetDescriptor,
    ObjectSetTraversal,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset};
use sekai_chisei::sekai::definition_branch::{
    DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
};
use sekai_chisei::sekai::object_log::{CANARY_OUTCOMES_METRIC, ObjectLogDualRead};
use sekai_chisei::sekai::object_set::CONTRACT_VERSION_V2;
use sekai_chisei::sekai::object_type_index::{CONTRACT_VERSION, ObjectTypeDatasource};
use sekai_chisei::sekai::security::Role;
use sekai_chisei::sekai::synthetic::Rng;
use tonic::Request;
use tonic::metadata::MetadataValue;

/// Seeds the default run checks. A seed that once found a defect joins this
/// list once the defect is fixed.
const FIXED_SEEDS: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 4711];
/// Named regression cases: what each one caught, its seed, and its writes.
/// The default run checks these alongside the fixed seeds.
const REGRESSION_CASES: &[(&str, u64, usize)] = &[
    // An incoming hop compared as outgoing (#989, #2412).
    ("incoming hop follows the near row's join property", 8, 2),
    // A namespace the log never saw refused the evaluate (#2419), in the
    // first namespace and in the second.
    ("unseen namespace compares as empty", 3, 1),
    ("unseen second namespace compares as empty", 4711, 1),
];
/// Writes per case in the default run.
const DEFAULT_OPS: usize = 40;
/// Requests run after every this many writes, and after the last.
const CHECKPOINT_EVERY: usize = 10;
const REQUESTS_PER_CHECKPOINT: usize = 6;
const PRINCIPAL: &str = "local";
const TAGS: [&str; 3] = ["red", "blue", "green"];
const NAMESPACES: [&str; 2] = ["diff-a", "diff-b"];

/// The kinds of one case, a chain `K0 -> K1 -> ...` where `Ki+1` carries
/// `ki_id`, the key of its `Ki`. Every kind carries a numeric `val` (the
/// measure) and a string `tag` that is sometimes absent (filters and the
/// absent group).
#[derive(Clone)]
struct Schema {
    namespaces: usize,
    kinds: usize,
}

impl Schema {
    fn kind(index: usize) -> String {
        format!("K{index}")
    }

    fn link(index: usize) -> String {
        format!("l{index}")
    }

    /// The property of `Ki+1` that names its `Ki`.
    fn join(index: usize) -> String {
        format!("k{index}_id")
    }

    fn properties(&self, kind: usize) -> Vec<String> {
        let mut properties = vec!["val".to_string(), "tag".to_string()];
        if kind > 0 {
            properties.push(Self::join(kind - 1));
        }
        properties
    }
}

/// One write to both engines: an object version, or its hiding.
#[derive(Clone, Debug)]
struct Write {
    namespace: usize,
    kind: usize,
    key: String,
    hidden: bool,
    props: BTreeMap<String, String>,
}

/// A request, as the descriptor the service evaluates.
#[derive(Clone, Debug)]
struct Query {
    namespace: usize,
    root: usize,
    hops: Vec<ObjectSetTraversal>,
    filter: Option<PropertyFilter>,
    function: &'static str,
    group_by: String,
    limit: i32,
}

/// Everything a seed generates. The writes and each checkpoint's requests
/// come from separate streams, so a shorter prefix of the writes still
/// meets the same requests.
struct Case {
    seed: u64,
    schema: Schema,
    writes: Vec<Write>,
}

impl Case {
    fn generate(seed: u64, ops: usize) -> Self {
        let mut rng = Rng::new(seed);
        let schema = Schema {
            namespaces: 1 + rng.below(2),
            kinds: 2 + rng.below(3),
        };
        let mut writes: Vec<Write> = Vec::with_capacity(ops);
        // The latest visible version of each identity.
        let mut live: BTreeMap<(usize, usize, String), BTreeMap<String, String>> = BTreeMap::new();
        let mut next_key = 0usize;
        while writes.len() < ops {
            let existing: Vec<_> = live.keys().cloned().collect();
            let write = match rng.below(10) {
                // A newer generation of a live identity.
                0 | 1 if !existing.is_empty() => {
                    let (namespace, kind, key) = existing[rng.below(existing.len())].clone();
                    let props = props_for(&mut rng, &schema, namespace, kind, &live, false);
                    Write {
                        namespace,
                        kind,
                        key,
                        hidden: false,
                        props,
                    }
                }
                // Hiding a live identity.
                2 if !existing.is_empty() => {
                    let identity = existing[rng.below(existing.len())].clone();
                    let props = live[&identity].clone();
                    let (namespace, kind, key) = identity;
                    Write {
                        namespace,
                        kind,
                        key,
                        hidden: true,
                        props,
                    }
                }
                // The same key in the other namespace.
                3 if schema.namespaces > 1 && !existing.is_empty() => {
                    let (namespace, kind, key) = existing[rng.below(existing.len())].clone();
                    let namespace = 1 - namespace;
                    let props = props_for(&mut rng, &schema, namespace, kind, &live, false);
                    Write {
                        namespace,
                        kind,
                        key,
                        hidden: false,
                        props,
                    }
                }
                // A new object, whose link may name a missing key.
                choice => {
                    let namespace = rng.below(schema.namespaces);
                    let kind = rng.below(schema.kinds);
                    next_key += 1;
                    let dangling = choice == 4;
                    let props = props_for(&mut rng, &schema, namespace, kind, &live, dangling);
                    Write {
                        namespace,
                        kind,
                        key: format!("o{next_key}"),
                        hidden: false,
                        props,
                    }
                }
            };
            let identity = (write.namespace, write.kind, write.key.clone());
            if write.hidden {
                live.remove(&identity);
            } else {
                live.insert(identity, write.props.clone());
            }
            writes.push(write);
        }
        Self {
            seed,
            schema,
            writes,
        }
    }

    /// The requests of checkpoint `index`.
    fn queries(&self, index: usize) -> Vec<Query> {
        let mut rng = Rng::new(self.seed ^ (index as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        (0..REQUESTS_PER_CHECKPOINT)
            .map(|_| {
                let namespace = rng.below(self.schema.namespaces);
                let root = rng.below(self.schema.kinds);
                let mut hops = Vec::new();
                let mut near = root;
                for _ in 0..rng.below(3) {
                    // Mostly toward the children; sometimes toward the parent.
                    if rng.below(6) == 0 && near > 0 {
                        hops.push(ObjectSetTraversal {
                            relation: Schema::link(near - 1),
                            direction: "incoming".into(),
                            far_kind: Schema::kind(near - 1),
                            join_property: Schema::join(near - 1),
                        });
                        near -= 1;
                    } else if near + 1 < self.schema.kinds {
                        hops.push(ObjectSetTraversal {
                            relation: Schema::link(near),
                            direction: "outgoing".into(),
                            far_kind: Schema::kind(near + 1),
                            join_property: Schema::join(near),
                        });
                        near += 1;
                    }
                }
                let filter = (rng.below(4) == 0).then(|| PropertyFilter {
                    key: "tag".into(),
                    op: "eq".into(),
                    value: TAGS[rng.below(TAGS.len())].into(),
                });
                let function = ["count", "sum", "min", "max", "avg"][rng.below(5)];
                // Every aggregated request groups by a root property.
                let group_by = self.schema.properties(root)
                    [rng.below(self.schema.properties(root).len())]
                .clone();
                Query {
                    namespace,
                    root,
                    hops,
                    filter,
                    function,
                    group_by,
                    limit: [0, 1, 5, 50][rng.below(4)],
                }
            })
            .collect()
    }
}

/// A new version's properties. A link names a live parent in the same
/// namespace, a missing key when `dangling`, or nothing when there is none.
fn props_for(
    rng: &mut Rng,
    schema: &Schema,
    namespace: usize,
    kind: usize,
    live: &BTreeMap<(usize, usize, String), BTreeMap<String, String>>,
    dangling: bool,
) -> BTreeMap<String, String> {
    let mut props = BTreeMap::from([("val".to_string(), rng.below(10).to_string())]);
    if let Some(tag) = [None, Some("red"), Some("blue")][rng.below(3)] {
        props.insert("tag".to_string(), tag.to_string());
    }
    if kind > 0 {
        let parents: Vec<&String> = live
            .keys()
            .filter(|(ns, k, _)| *ns == namespace && *k == kind - 1)
            .map(|(_, _, key)| key)
            .collect();
        let parent = if dangling || parents.is_empty() {
            format!("missing-{}", rng.below(4))
        } else {
            parents[rng.below(parents.len())].clone()
        };
        let _ = schema;
        props.insert(Schema::join(kind - 1), parent);
    }
    props
}

/// How one run of a case ended.
#[derive(Default)]
struct Tally {
    compared: usize,
    skipped: usize,
}

/// The first disagreement of a run: the gate's report.
struct Mismatch(String);

/// Runs the first `ops` writes of `case`, with the requests of every
/// checkpoint on the way.
async fn run(case: &Case, ops: usize, tally: &mut Tally) -> Result<(), Mismatch> {
    let dir = tempfile::tempdir().expect("temporary directory");
    let db = Arc::new(RuntimeDb::memory());
    for namespace in &NAMESPACES[..case.schema.namespaces] {
        db.ensure_team_namespace(namespace, PRINCIPAL, Role::Admin, PRINCIPAL)
            .expect("namespace");
    }
    let digests: Vec<String> = NAMESPACES[..case.schema.namespaces]
        .iter()
        .map(|namespace| publish_schema(&db, namespace, &case.schema))
        .collect();
    let service = SekaiServiceImpl::new(SekaiStore::from_shared_runtime(db.clone()));
    let mut generations: HashMap<(usize, usize, String), u64> = HashMap::new();
    let mut records = Vec::with_capacity(ops);
    for (index, write) in case.writes[..ops].iter().enumerate() {
        let mut row = HashMap::from([
            ("key".to_string(), write.key.clone()),
            (
                "hidden".to_string(),
                if write.hidden { "true" } else { "0" }.to_string(),
            ),
        ]);
        row.extend(write.props.clone());
        db.append_rows(&dataset_id(write.namespace, write.kind), &[row])
            .expect("dataset row");
        let generation = generations
            .entry((write.namespace, write.kind, write.key.clone()))
            .or_default();
        *generation += 1;
        records.push(mikura::ObjectRecord {
            action_id: None,
            r#gen: *generation,
            namespace: NAMESPACES[write.namespace].into(),
            kind: Schema::kind(write.kind),
            key: write.key.clone(),
            hidden: write.hidden,
            props: write.props.clone().into_iter().collect(),
            schema_version: 1,
        });
        let done = index + 1;
        if done % CHECKPOINT_EVERY != 0 && done != ops {
            continue;
        }
        for namespace in &NAMESPACES[..case.schema.namespaces] {
            for kind in 0..case.schema.kinds {
                db.apply_object_type_index(namespace, &Schema::kind(kind), false, 30)
                    .expect("index apply");
            }
        }
        // A fresh log per checkpoint: the gate keeps its writer open on the
        // file it last read, so this test never writes to that one again.
        let checkpoint = done.div_ceil(CHECKPOINT_EVERY);
        let log = dir.path().join(format!("objects-{done}.mikura"));
        write_log(&log, &records);
        let service = service
            .clone()
            .with_object_log_dual_read(ObjectLogDualRead {
                enabled: true,
                log_path: Some(log),
                sample_n: 1,
            });
        for query in case.queries(checkpoint) {
            let before = outcomes().snapshot();
            evaluate(&service, &query, &digests[query.namespace]).await?;
            match outcomes().snapshot().since(&before) {
                Outcome::Compared => tally.compared += 1,
                Outcome::Skipped => tally.skipped += 1,
                outcome => panic!("gate recorded {outcome:?} without failing {query:?}"),
            }
        }
    }
    Ok(())
}

/// Evaluates `query`; the gate's refusal is the mismatch. Any other error is
/// a generator defect and fails the test outright.
async fn evaluate(service: &SekaiServiceImpl, query: &Query, digest: &str) -> Result<(), Mismatch> {
    let mut request = Request::new(EvaluateObjectSetRequest {
        descriptor: Some(ObjectSetDescriptor {
            contract_version: CONTRACT_VERSION_V2.into(),
            namespace: NAMESPACES[query.namespace].into(),
            kind: Schema::kind(query.root),
            definition_digest: digest.into(),
            hops: query.hops.clone(),
            property_filters: query
                .filter
                .iter()
                .map(|filter| sekai_chisei::grpc::pb::sekai::PropertyFilter {
                    key: filter.key.clone(),
                    op: filter.op.clone(),
                    value: filter.value.clone(),
                })
                .collect(),
            aggregation: Some(ObjectSetAggregation {
                function: query.function.into(),
                property: if query.function == "count" {
                    String::new()
                } else {
                    "val".into()
                },
                group_by: query.group_by.clone(),
            }),
            limit: query.limit,
            cost_limit: Some(ObjectSetCostLimit {
                max_rows_scanned: 1_000_000,
                max_depth: 3,
                max_time_ms: 0,
            }),
            ..Default::default()
        }),
        page_token: String::new(),
        required_freshness_ms: 0,
    });
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(PRINCIPAL));
    match service.evaluate_object_set(request).await {
        Ok(_) => Ok(()),
        Err(status) if status.message().starts_with("object-log ") => {
            Err(Mismatch(format!("{} for {query:?}", status.message())))
        }
        Err(status) => panic!("request the generator should not make: {query:?}: {status}"),
    }
}

/// What the gate recorded for one request.
#[derive(Debug, PartialEq)]
enum Outcome {
    Compared,
    Skipped,
    Other,
}

/// Counts of the gate's outcome counter, by `outcome` label, plus skip
/// reasons for the report. Installed as this binary's global recorder: the
/// binary holds one test, so the counts are only ever this test's.
#[derive(Default)]
struct Outcomes {
    compared: AtomicU64,
    skipped: AtomicU64,
    other: AtomicU64,
    reasons: Mutex<BTreeMap<String, u64>>,
}

#[derive(Clone, Copy)]
struct OutcomeCounts([u64; 3]);

impl OutcomeCounts {
    /// The one outcome recorded since `before`.
    fn since(&self, before: &Self) -> Outcome {
        match [0, 1, 2].map(|i| self.0[i] - before.0[i]) {
            [1, 0, 0] => Outcome::Compared,
            [0, 1, 0] => Outcome::Skipped,
            delta => {
                assert!(delta != [0, 0, 0], "the gate recorded no outcome");
                Outcome::Other
            }
        }
    }
}

impl Outcomes {
    fn snapshot(&self) -> OutcomeCounts {
        OutcomeCounts([
            self.compared.load(Ordering::SeqCst),
            self.skipped.load(Ordering::SeqCst),
            self.other.load(Ordering::SeqCst),
        ])
    }
}

/// One labelled series of the gate's counter.
struct OutcomeSeries {
    outcomes: &'static Outcomes,
    outcome: String,
    reason: String,
}

impl metrics::CounterFn for OutcomeSeries {
    fn increment(&self, value: u64) {
        let slot = match self.outcome.as_str() {
            "compared" => &self.outcomes.compared,
            "skipped" => {
                *self
                    .outcomes
                    .reasons
                    .lock()
                    .unwrap()
                    .entry(self.reason.clone())
                    .or_default() += value;
                &self.outcomes.skipped
            }
            _ => &self.outcomes.other,
        };
        slot.fetch_add(value, Ordering::SeqCst);
    }

    fn absolute(&self, _: u64) {}
}

struct OutcomeRecorder(&'static Outcomes);

impl metrics::Recorder for OutcomeRecorder {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        if key.name() != CANARY_OUTCOMES_METRIC {
            return metrics::Counter::noop();
        }
        let label = |name: &str| {
            key.labels()
                .find(|label| label.key() == name)
                .map(|label| label.value().to_string())
                .unwrap_or_default()
        };
        metrics::Counter::from_arc(Arc::new(OutcomeSeries {
            outcomes: self.0,
            outcome: label("outcome"),
            reason: label("reason"),
        }))
    }

    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }

    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

fn outcomes() -> &'static Outcomes {
    static OUTCOMES: OnceLock<&'static Outcomes> = OnceLock::new();
    OUTCOMES.get_or_init(|| {
        let outcomes: &'static Outcomes = Box::leak(Box::default());
        metrics::set_global_recorder(OutcomeRecorder(outcomes))
            .expect("this test binary installs the only recorder");
        outcomes
    })
}

fn dataset_id(namespace: usize, kind: usize) -> String {
    format!("ds-{namespace}-{kind}")
}

/// Publishes the schema's kinds and links in `namespace`, and binds each
/// kind to an empty dataset the relational index projects.
fn publish_schema(db: &RuntimeDb, namespace: &str, schema: &Schema) -> String {
    let mut members = Vec::new();
    for kind in 0..schema.kinds {
        let properties: serde_json::Map<String, serde_json::Value> = schema
            .properties(kind)
            .into_iter()
            .map(|name| {
                let kind = if name == "val" { "number" } else { "string" };

                (name, serde_json::json!({ "type": kind }))
            })
            .collect();
        members.push(member(
            namespace,
            "object_type",
            &Schema::kind(kind),
            serde_json::json!({ "name": Schema::kind(kind), "properties": properties }),
        ));
        if kind + 1 < schema.kinds {
            members.push(member(
                namespace,
                "link_type",
                &Schema::link(kind),
                serde_json::json!({
                    "name": Schema::link(kind),
                    "from": Schema::kind(kind),
                    "to": Schema::kind(kind + 1),
                }),
            ));
        }
    }
    let revision = prepare_revision(
        namespace,
        "",
        members.iter().map(|item| DefinitionRevisionMember {
            member_kind: item.member_kind.clone(),
            member_id: item.member_id.clone(),
            member_digest: item.member_digest.clone(),
        }),
        true,
        PRINCIPAL,
        1,
    )
    .expect("revision");
    db.seed_published_definition_revision(&revision, &members)
        .expect("publish");
    let index = NAMESPACES.iter().position(|ns| *ns == namespace).unwrap();
    for kind in 0..schema.kinds {
        let properties = schema.properties(kind);
        let mut columns = vec!["key".to_string(), "hidden".to_string()];
        columns.extend(properties.iter().cloned());
        let dataset = dataset_id(index, kind);
        db.create_dataset(&Dataset {
            id: dataset.clone(),
            name: dataset.clone(),
            columns: columns
                .iter()
                .map(|name| ColumnDef {
                    name: name.clone(),
                    col_type: "string".into(),
                    classification: "public".into(),
                })
                .collect(),
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .expect("dataset");
        let binding = ObjectTypeDatasource {
            contract_version: CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            kind: Schema::kind(kind),
            definition_digest: revision.revision_digest.clone(),
            dataset_id: dataset,
            key_column: "key".into(),
            property_mapping: properties
                .iter()
                .map(|name| (name.clone(), name.clone()))
                .collect(),
            hidden_column: "hidden".into(),
            edits_only: false,
            conflict_rule: String::new(),
            source_timestamp_property: String::new(),
        }
        .prepare()
        .expect("datasource");
        db.register_object_type_datasource(&binding, 10)
            .expect("bind");
    }
    revision.revision_digest
}

fn member(
    namespace: &str,
    member_kind: &str,
    id: &str,
    definition: serde_json::Value,
) -> sekai_chisei::sekai::definition_branch::DefinitionMember {
    DefinitionMemberInput {
        member_kind: member_kind.into(),
        member_id: id.into(),
        definition_json: definition.to_string(),
        member_digest: String::new(),
    }
    .prepare(namespace)
    .expect("member")
}

/// Writes `records` into a new log at `path`, one batch per record so each
/// generation commits in order.
fn write_log(path: &Path, records: &[mikura::ObjectRecord]) {
    let mut store = mikura::Store::create(path).expect("log");
    for record in records {
        mikura_ingest::BatchIngest::run(&mut store, vec![record.clone()]).expect("log record");
    }
}

/// Runs `case` and, on a mismatch, finds the shortest failing prefix.
/// Returns the report line, or `None` when the case passes.
async fn check(case: &Case, tally: &mut Tally) -> Option<String> {
    let ops = case.writes.len();
    let Err(Mismatch(first)) = run(case, ops, tally).await else {
        return None;
    };
    let mut shortest = (ops, first);
    for prefix in 1..ops {
        if let Err(Mismatch(found)) = run(case, prefix, &mut Tally::default()).await {
            shortest = (prefix, found);
            break;
        }
    }
    let (prefix, found) = shortest;
    Some(format!(
        "object-log differential: seed={} ops={prefix} mismatch: {found}\n\
         rerun: SEKAI_DIFF_SEED={} SEKAI_DIFF_OPS={prefix} cargo test --test object_log_differential",
        case.seed, case.seed
    ))
}

fn env_number(name: &str) -> Option<u64> {
    std::env::var(name).ok().map(|value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a number"))
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn the_object_log_agrees_with_the_relational_projection() {
    let ops = env_number("SEKAI_DIFF_OPS").map_or(DEFAULT_OPS, |ops| ops as usize);
    let cases: Vec<(u64, usize)> = match (
        env_number("SEKAI_DIFF_SEED"),
        env_number("SEKAI_DIFF_CASES"),
    ) {
        (Some(seed), None) => vec![(seed, ops)],
        (start, Some(cases)) => {
            let start = start.unwrap_or(1);
            (start..start + cases).map(|seed| (seed, ops)).collect()
        }
        (None, None) => FIXED_SEEDS
            .iter()
            .map(|&seed| (seed, ops))
            .chain(REGRESSION_CASES.iter().map(|&(_, seed, ops)| (seed, ops)))
            .collect(),
    };
    let mut tally = Tally::default();
    let mut failures = Vec::new();
    for (seed, ops) in cases {
        let case = Case::generate(seed, ops);
        if let Some(report) = check(&case, &mut tally).await {
            failures.push(report);
        }
    }
    println!(
        "object-log differential: compared={} skipped={}",
        tally.compared, tally.skipped
    );
    for (reason, count) in outcomes().reasons.lock().unwrap().iter() {
        println!("  skipped {count}: {reason}");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        tally.compared * 2 >= tally.compared + tally.skipped,
        "fewer than half of the requests were compared: compared={} skipped={}",
        tally.compared,
        tally.skipped
    );
}
