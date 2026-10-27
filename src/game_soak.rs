//! Game soak harness (#1626).
//!
//! Drives the game reference workload ([`GameWorkload`]) against a running
//! deployment through public gRPC, so combined-throughput regressions show
//! up early in a sustained, reproducible run:
//!
//! - **Bots** each command a disjoint share of the tenant's fleets and
//!   propose governed `game.fleet.order` Actions, one per round. The plane
//!   admits and applies each proposal.
//! - **Intake** delivers each round's battle reports as one registered-source
//!   `ApplySourceBatch` and appends the same events to a dataset.
//! - **Statistics** is a governed analytical transform over that dataset,
//!   run after every intake batch; each run names its predecessor as its
//!   lineage parent.
//!
//! [`script`] is a pure function of the seed: the tenant, every bot order
//! and every battle report. [`run`] plays a script against a target and
//! returns a [`SoakReport`], which writes the throughput document. Setup
//! runs as the local operator (Unix socket); bots and intake use their own
//! bearer credentials, created through the same public surface.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tonic::{Code, Request, Status};

use crate::grpc::client::{GatewayClient, connect_sekai};
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    AppendRowsRequest, ApplySourceBatchRequest, ColumnDef, CreateCredentialRequest,
    CreateDatasetRequest, CreateLinkRequest, CreateObjectRequest, CreateSchemaTypeRequest, Dataset,
    EnsureTeamNamespaceRequest, GovernedActionType, GovernedTransform, Link, Object, ObjectType,
    PropertyDef, PutGovernedActionTypeRequest, PutGovernedTransformRequest,
    RegisterSourceTypeDescriptorRequest, RotateCredentialRequest, Row, RunGovernedTransformRequest,
    SourceBatch, SourceRecord, SubmitActionInstanceRequest,
};
use crate::sekai::governed_transform::{ANALYTICAL_CLASS, CONTRACT_VERSION};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
use crate::sekai::synthetic::{Rng, SizePreset, Spec, SyntheticPlan, generate};
use crate::sekai::synthetic_game::GameWorkload;
use sekai_source_sdk::{
    ADAPTER_REGISTERED_OBJECT_SYNC, ADAPTER_REGISTERED_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    MAX_SOURCE_BATCH_RECORDS, SOURCE_BATCH_VERSION,
};

pub const REPORT_VERSION: &str = "sekai.game-soak-report/v1";
const FLEET_KIND: &str = "game_fleet";
const PLANET_KIND: &str = "game_planet";
const EVENT_SOURCE: &str = "game.events";
const EVENT_KIND: &str = "game_battle";
const EVENT_SCHEMA_REVISION: &str = "1";
const EVENT_COLUMNS: &[&str] = &["round", "fleet", "planet", "ships_lost", "outcome"];
const OUTCOMES: &[&str] = &["won", "lost", "draw"];
const STATS_TRANSFORM: &str = "fleet-stats";
const STATS_SQL: &str = "SELECT fleet, COUNT(*) AS battles, \
    SUM(CAST(ships_lost AS INTEGER)) AS ships_lost FROM input GROUP BY fleet ORDER BY fleet";
/// Keeps the bot stream apart from the tenant generator's stream.
const BOT_STREAM: u64 = 0x6761_6d65_736f_616b;

/// What to play: the tenant size and how hard to drive it.
#[derive(Debug, Clone)]
pub struct SoakSpec {
    pub seed: u64,
    pub preset: SizePreset,
    pub bots: usize,
    pub rounds: usize,
    /// Battle reports per intake batch.
    pub batch_records: usize,
}

/// One governed Action a bot proposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BotOrder {
    pub round: usize,
    pub bot: usize,
    /// Index of the ordered fleet in the plan's objects.
    pub fleet: usize,
    pub orders: String,
}

/// One battle report in an intake batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BattleEvent {
    pub fleet: usize,
    pub planet: String,
    pub ships_lost: usize,
    pub outcome: &'static str,
}

/// Everything a soak run plays, derived only from the spec and namespace.
pub struct GameScript {
    pub spec: SoakSpec,
    pub plan: SyntheticPlan,
    /// Orders in round order, then bot order.
    pub orders: Vec<BotOrder>,
    /// Battle reports, one batch per round.
    pub events: Vec<Vec<BattleEvent>>,
    /// SHA-256 over `orders`; independent of the namespace.
    pub action_digest: String,
}

#[derive(Debug)]
pub enum SoakError {
    /// The spec cannot be played.
    Spec(String),
    Connect(String),
    /// The target refused a call.
    Rpc {
        step: &'static str,
        status: Status,
    },
    /// The run finished but did not do what the script says.
    Invariant(String),
    Io(std::io::Error),
}

impl std::fmt::Display for SoakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spec(message) => write!(f, "invalid soak spec: {message}"),
            Self::Connect(message) => write!(f, "connect: {message}"),
            Self::Rpc { step, status } => {
                write!(f, "{step}: {:?} {}", status.code(), status.message())
            }
            Self::Invariant(message) => write!(f, "soak invariant failed: {message}"),
            Self::Io(error) => write!(f, "write report: {error}"),
        }
    }
}

impl std::error::Error for SoakError {}

fn rpc(step: &'static str) -> impl FnOnce(Status) -> SoakError {
    move |status| SoakError::Rpc { step, status }
}

/// Build the script for `spec` in `namespace`. The same seed and spec give
/// the same orders and the same `action_digest` in any namespace.
pub fn script(spec: &SoakSpec, namespace: &str) -> Result<GameScript, SoakError> {
    if spec.bots == 0 || spec.rounds == 0 || spec.batch_records == 0 {
        return Err(SoakError::Spec(
            "bots, rounds and batch records must be positive".into(),
        ));
    }
    if spec.batch_records > MAX_SOURCE_BATCH_RECORDS {
        return Err(SoakError::Spec(format!(
            "at most {MAX_SOURCE_BATCH_RECORDS} records per batch"
        )));
    }
    let plan = generate(
        &GameWorkload,
        &Spec {
            namespace: namespace.into(),
            seed: spec.seed,
            preset: spec.preset,
        },
    )
    .map_err(SoakError::Spec)?;
    let indices = |kind: &str| -> Vec<usize> {
        plan.objects
            .iter()
            .enumerate()
            .filter(|(_, object)| object.kind == kind)
            .map(|(index, _)| index)
            .collect()
    };
    let fleets = indices(FLEET_KIND);
    let planets: Vec<&str> = indices(PLANET_KIND)
        .into_iter()
        .map(|index| plan.objects[index].properties["coordinates"].as_str())
        .collect();
    if spec.bots > fleets.len() {
        return Err(SoakError::Spec(format!(
            "{} bots need at least as many fleets; the {} preset has {}",
            spec.bots,
            spec.preset.name(),
            fleets.len()
        )));
    }
    // Bot `b` commands every fleet whose position is `b` modulo the bot
    // count, so no two bots ever order the same fleet.
    let commands: Vec<Vec<usize>> = (0..spec.bots)
        .map(|bot| {
            fleets
                .iter()
                .copied()
                .skip(bot)
                .step_by(spec.bots)
                .collect()
        })
        .collect();
    let mut rng = Rng::new(spec.seed ^ BOT_STREAM);
    let mut orders = Vec::with_capacity(spec.rounds * spec.bots);
    let mut events = Vec::with_capacity(spec.rounds);
    for round in 0..spec.rounds {
        for (bot, fleets) in commands.iter().enumerate() {
            let fleet = fleets[rng.below(fleets.len())];
            let orders_text = match rng.below(4) {
                0 => "hold".to_string(),
                1 => "patrol".to_string(),
                _ => format!("move:{}", planets[rng.below(planets.len())]),
            };
            orders.push(BotOrder {
                round,
                bot,
                fleet,
                orders: orders_text,
            });
        }
        events.push(
            (0..spec.batch_records)
                .map(|_| BattleEvent {
                    fleet: fleets[rng.below(fleets.len())],
                    planet: planets[rng.below(planets.len())].to_string(),
                    ships_lost: rng.below(50),
                    outcome: rng.pick(OUTCOMES),
                })
                .collect(),
        );
    }
    let canonical =
        serde_json::to_vec(&orders).map_err(|error| SoakError::Spec(error.to_string()))?;
    let action_digest = format!("{:x}", Sha256::digest(canonical));
    Ok(GameScript {
        spec: spec.clone(),
        plan,
        orders,
        events,
        action_digest,
    })
}

impl GameScript {
    /// The principal bot `bot` (zero-based) acts as.
    pub fn bot_principal(&self, bot: usize) -> String {
        format!("{}.bot-{:02}", self.plan.namespace, bot + 1)
    }

    /// Each bot's governed Action proposals, in the order it submits them.
    pub fn proposals(&self) -> Vec<Vec<SubmitActionInstanceRequest>> {
        let namespace = &self.plan.namespace;
        let mut per_bot = vec![Vec::new(); self.spec.bots];
        for order in &self.orders {
            let key = format!("{namespace}-r{:06}-b{:02}", order.round, order.bot + 1);
            per_bot[order.bot].push(SubmitActionInstanceRequest {
                namespace: namespace.clone(),
                type_id: self.plan.action_types[0].type_id.clone(),
                version: self.plan.action_types[0].version.clone(),
                parameters_json: serde_json::json!({
                    "object_id": self.plan.objects[order.fleet].id,
                    "orders": order.orders,
                })
                .to_string(),
                request_id: format!("operation-{key}"),
                idempotency_key: key,
                ..Default::default()
            });
        }
        per_bot
    }
}

/// Environment metadata recorded with a report. Every field is generic:
/// no host name, user name or path.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareProfile {
    pub description: String,
    pub cores: usize,
    pub operating_system: String,
    pub rustc: String,
    pub build_profile: String,
}

/// Nearest-rank latency summary in milliseconds.
#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

impl Latency {
    fn of(samples: &[Duration]) -> Self {
        let mut ms: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1e3).collect();
        ms.sort_by(f64::total_cmp);
        let rank = |p: f64| {
            if ms.is_empty() {
                return 0.0;
            }
            let index = ((p * ms.len() as f64).ceil() as usize).clamp(1, ms.len()) - 1;
            round3(ms[index])
        };
        Self {
            p50_ms: rank(0.50),
            p95_ms: rank(0.95),
            p99_ms: rank(0.99),
            max_ms: rank(1.0),
        }
    }
}

fn round3(value: f64) -> f64 {
    (value * 1e3).round() / 1e3
}

fn per_second(count: usize, elapsed: Duration) -> f64 {
    round3(count as f64 / elapsed.as_secs_f64().max(f64::EPSILON))
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkloadSummary {
    pub seed: u64,
    pub preset: &'static str,
    pub objects: usize,
    pub bots: usize,
    pub rounds: usize,
    pub batch_records: usize,
    pub action_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionMetrics {
    pub proposed: usize,
    pub applied: usize,
    /// Time spent in this path's calls; rates divide by it.
    pub seconds: f64,
    pub per_second: f64,
    pub latency: Latency,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntakeMetrics {
    pub batches: usize,
    pub records: usize,
    /// Time spent in this path's calls; rates divide by it.
    pub seconds: f64,
    pub batches_per_second: f64,
    pub records_per_second: f64,
    /// One ApplySourceBatch plus the dataset append for the same events.
    pub latency: Latency,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransformMetrics {
    pub runs: usize,
    /// Every run named the previous run as its lineage parent.
    pub lineage_chained: bool,
    /// Rows the last run wrote: one per fleet that fought.
    pub output_rows: i32,
    /// Client-observed RunGovernedTransform latency.
    pub latency: Latency,
}

/// The result of one soak run; it writes the throughput document.
#[derive(Debug, Clone, Serialize)]
pub struct SoakReport {
    pub contract_version: &'static str,
    pub recorded_at: String,
    pub crate_version: &'static str,
    pub hardware: HardwareProfile,
    pub workload: WorkloadSummary,
    pub wall_seconds: f64,
    pub actions: ActionMetrics,
    pub intake: IntakeMetrics,
    pub transform: TransformMetrics,
}

impl SoakReport {
    /// The human-readable throughput document.
    pub fn markdown(&self) -> String {
        let latency = |l: &Latency| {
            format!(
                "p50 {} ms, p95 {} ms, p99 {} ms, max {} ms",
                l.p50_ms, l.p95_ms, l.p99_ms, l.max_ms
            )
        };
        let w = &self.workload;
        let h = &self.hardware;
        format!(
            "# Game soak throughput\n\n\
             Generated by `game-soak` ({contract}); do not edit by hand.\n\n\
             ## Environment\n\n\
             | | |\n| --- | --- |\n\
             | Recorded | {recorded} |\n\
             | Hardware | {hardware} |\n\
             | Cores | {cores} |\n\
             | Operating system | {os} |\n\
             | Compiler | {rustc} |\n\
             | Build profile | {profile} |\n\
             | Crate version | {crate_version} |\n\n\
             ## Workload\n\n\
             | | |\n| --- | --- |\n\
             | Seed | {seed} |\n\
             | Tenant preset | {preset} ({objects} objects) |\n\
             | Bots | {bots} |\n\
             | Rounds | {rounds} |\n\
             | Records per intake batch | {batch_records} |\n\
             | Action sequence digest | `{digest}` |\n\
             | Wall time | {wall} s |\n\n\
             ## Results\n\n\
             Paths interleave one call at a time; each rate divides by the time spent in that path's calls.\n\n\
             | Path | Throughput | Latency |\n| --- | --- | --- |\n\
             | Actions ({applied}/{proposed} applied) | {aps} Actions/s | {alat} |\n\
             | Intake ({batches} batches, {records} records) | {bps} batches/s, {rps} records/s | {ilat} |\n\
             | Statistics transform ({runs} runs, lineage chained: {chained}, {rows} output rows) | | {tlat} |\n",
            contract = self.contract_version,
            recorded = self.recorded_at,
            hardware = h.description,
            cores = h.cores,
            os = h.operating_system,
            rustc = h.rustc,
            profile = h.build_profile,
            crate_version = self.crate_version,
            seed = w.seed,
            preset = w.preset,
            objects = w.objects,
            bots = w.bots,
            rounds = w.rounds,
            batch_records = w.batch_records,
            digest = w.action_digest,
            wall = self.wall_seconds,
            applied = self.actions.applied,
            proposed = self.actions.proposed,
            aps = self.actions.per_second,
            alat = latency(&self.actions.latency),
            batches = self.intake.batches,
            records = self.intake.records,
            bps = self.intake.batches_per_second,
            rps = self.intake.records_per_second,
            ilat = latency(&self.intake.latency),
            runs = self.transform.runs,
            chained = self.transform.lineage_chained,
            rows = self.transform.output_rows,
            tlat = latency(&self.transform.latency),
        )
    }

    /// Write `report.json` and `report.md` into `dir`.
    pub fn write(&self, dir: &Path) -> Result<(), SoakError> {
        std::fs::create_dir_all(dir).map_err(SoakError::Io)?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|error| SoakError::Io(std::io::Error::other(error)))?;
        std::fs::write(dir.join("report.json"), json + "\n").map_err(SoakError::Io)?;
        std::fs::write(dir.join("report.md"), self.markdown()).map_err(SoakError::Io)
    }
}

type Client = SekaiServiceClient<GatewayClient>;

fn bearer<T>(token: &str, message: T) -> Result<Request<T>, SoakError> {
    let mut request = Request::new(message);
    let value = format!("Bearer {token}")
        .parse()
        .map_err(|_| SoakError::Invariant("credential is not valid metadata".into()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

/// Accept an "already exists" answer, so shared definitions such as object
/// kinds can be ensured by every run on one deployment.
fn ensured<T>(result: Result<T, Status>, step: &'static str) -> Result<(), SoakError> {
    match result {
        Ok(_) => Ok(()),
        Err(status)
            if status.code() == Code::AlreadyExists || status.message().contains("already") =>
        {
            Ok(())
        }
        Err(status) => Err(SoakError::Rpc { step, status }),
    }
}

fn schema_type(object_type: &crate::sekai::schema::ObjectType) -> ObjectType {
    ObjectType {
        kind: object_type.kind.clone(),
        description: object_type.description.clone(),
        properties: object_type
            .properties
            .iter()
            .map(|property| PropertyDef {
                name: property.name.clone(),
                r#type: property.prop_type.as_str().into(),
                required: property.required,
                description: property.description.clone(),
                enum_values: property.enum_values.clone(),
                classification: property.classification.clone(),
                ..Default::default()
            })
            .collect(),
        is_builtin: false,
        implements: object_type.implements.clone(),
    }
}

fn action_type(
    action_type: &crate::sekai::governed_action_type::GovernedActionType,
) -> GovernedActionType {
    GovernedActionType {
        namespace: action_type.namespace.clone(),
        type_id: action_type.type_id.clone(),
        version: action_type.version.clone(),
        description: action_type.description.clone(),
        parameter_schema_json: action_type.parameter_schema_json.clone(),
        allowed_effect_kinds: action_type.allowed_effect_kinds.clone(),
        object_kind: action_type.object_kind.clone(),
        object_mutation: action_type.object_mutation.clone(),
        enabled: true,
        ..Default::default()
    }
}

/// A credential for `principal`, rotated when one already exists.
async fn credential(operator: &mut Client, principal: &str) -> Result<String, SoakError> {
    let created = operator
        .create_credential(CreateCredentialRequest {
            principal: principal.into(),
            ..Default::default()
        })
        .await;
    let token = match created {
        Ok(response) => response.into_inner().token,
        Err(status) if status.code() == Code::AlreadyExists => {
            operator
                .rotate_credential(RotateCredentialRequest {
                    principal: principal.into(),
                    ..Default::default()
                })
                .await
                .map_err(rpc("rotate credential"))?
                .into_inner()
                .token
        }
        Err(status) => return Err(rpc("create credential")(status)),
    };
    Ok(token)
}

/// What setup leaves behind for the drive phase.
struct Deployment {
    bot_tokens: Vec<String>,
    producer: String,
    producer_token: String,
    type_digest: String,
    events_dataset: String,
}

/// Install the script's tenant, principals, Action type, event source,
/// datasets and statistics transform. The namespace must be fresh; kinds
/// are shared across runs and are only ensured.
async fn setup(operator: &mut Client, script: &GameScript) -> Result<Deployment, SoakError> {
    let plan = &script.plan;
    let namespace = &plan.namespace;
    for object_type in &plan.types {
        let created = operator
            .create_schema_type(CreateSchemaTypeRequest {
                r#type: Some(schema_type(object_type)),
            })
            .await;
        ensured(created, "create schema type")?;
    }
    let producer = format!("{namespace}.intake");
    let principals = (0..script.spec.bots)
        .map(|bot| script.bot_principal(bot))
        .chain([producer.clone()]);
    let mut tokens = Vec::new();
    let mut boundary = String::new();
    for principal in principals {
        tokens.push(credential(operator, &principal).await?);
        boundary = operator
            .ensure_team_namespace(EnsureTeamNamespaceRequest {
                namespace: namespace.clone(),
                principal,
                role: "editor".into(),
            })
            .await
            .map_err(rpc("grant namespace"))?
            .into_inner()
            .namespace
            .map(|object| object.id)
            .unwrap_or_default();
    }
    let producer_token = tokens.pop().unwrap_or_default();
    for object in &plan.objects {
        // Markings exercise clearance, not throughput; the soak tenant is
        // unmarked so every bot may order every fleet it commands.
        let mut properties = object.properties.clone();
        properties.remove(OBJECT_CLASSIFICATION_PROPERTY);
        operator
            .create_object(CreateObjectRequest {
                object: Some(Object {
                    id: object.id.clone(),
                    kind: object.kind.clone(),
                    name: object.name.clone(),
                    namespace: namespace.clone(),
                    external_id: object.id.clone(),
                    properties,
                    created: object.created,
                    updated: object.updated,
                }),
                lease_precondition: None,
            })
            .await
            .map_err(rpc("create object"))?;
    }
    for link in &plan.links {
        operator
            .create_link(CreateLinkRequest {
                link: Some(Link {
                    id: link.id.clone(),
                    from_id: link.from_id.clone(),
                    to_id: link.to_id.clone(),
                    relation: link.relation.clone(),
                    created: link.created,
                }),
                fail_if_exists: true,
            })
            .await
            .map_err(rpc("create link"))?;
    }
    for definition in &plan.action_types {
        operator
            .put_governed_action_type(PutGovernedActionTypeRequest {
                r#type: Some(action_type(definition)),
                request_id: String::new(),
            })
            .await
            .map_err(rpc("put action type"))?;
    }
    let type_digest = operator
        .register_source_type_descriptor(RegisterSourceTypeDescriptorRequest {
            namespace: namespace.clone(),
            source: EVENT_SOURCE.into(),
            record_kind: EVENT_KIND.into(),
            schema_revision: EVENT_SCHEMA_REVISION.into(),
        })
        .await
        .map_err(rpc("register event source"))?
        .into_inner()
        .descriptor
        .map(|descriptor| descriptor.digest)
        .ok_or_else(|| SoakError::Invariant("event source registered without a digest".into()))?;
    let events_dataset = format!("{namespace}.battles");
    let stats_dataset = format!("{namespace}.fleet-stats");
    let columns = |names: &[&str]| -> Vec<ColumnDef> {
        names
            .iter()
            .map(|name| ColumnDef {
                name: (*name).into(),
                r#type: "string".into(),
                classification: String::new(),
            })
            .collect()
    };
    for (id, names) in [
        (&events_dataset, EVENT_COLUMNS),
        (&stats_dataset, &["fleet", "battles", "ships_lost"][..]),
    ] {
        operator
            .create_dataset(CreateDatasetRequest {
                dataset: Some(Dataset {
                    id: id.clone(),
                    name: id.clone(),
                    columns: columns(names),
                    object_id: boundary.clone(),
                    ..Default::default()
                }),
            })
            .await
            .map_err(rpc("create dataset"))?;
    }
    operator
        .put_governed_transform(PutGovernedTransformRequest {
            transform: Some(GovernedTransform {
                contract_version: CONTRACT_VERSION.into(),
                namespace: namespace.clone(),
                transform_id: STATS_TRANSFORM.into(),
                input_dataset_id: events_dataset.clone(),
                output_dataset_id: stats_dataset,
                profile: ANALYTICAL_CLASS.into(),
                sql: STATS_SQL.into(),
                ..Default::default()
            }),
        })
        .await
        .map_err(rpc("put statistics transform"))?;
    Ok(Deployment {
        bot_tokens: tokens,
        producer,
        producer_token,
        type_digest,
        events_dataset,
    })
}

/// One round's battle reports as a registered-source batch moving the
/// checkpoint from `current` to the next round.
fn source_batch(
    script: &GameScript,
    deployment: &Deployment,
    round: usize,
    current: &str,
) -> Result<SourceBatch, SoakError> {
    let namespace = &script.plan.namespace;
    // Record identity does not include the namespace, so each soak world
    // is its own source instance.
    let records = script.events[round]
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let properties = event_row(script, round, event);
            let digest = Sha256::digest(
                serde_json::to_vec(&properties)
                    .map_err(|error| SoakError::Spec(error.to_string()))?,
            );
            Ok(sekai_source_sdk::SourceRecord {
                source: EVENT_SOURCE.into(),
                source_instance: namespace.clone(),
                external_id: format!("r{round:06}-e{index:04}"),
                source_version: "1".into(),
                type_name: EVENT_KIND.into(),
                display_name: format!("Battle {round}.{index}"),
                payload_digest: format!("sha256:{digest:x}"),
                properties,
                deleted: false,
                observed_at_ms: round as i64 + 1,
                source_sequence: None,
            })
        })
        .collect::<Result<Vec<_>, SoakError>>()?;
    let mut batch = sekai_source_sdk::SourceBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: namespace.clone(),
        producer_identity: deployment.producer.clone(),
        source: EVENT_SOURCE.into(),
        source_instance: namespace.clone(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_REGISTERED_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_REGISTERED_OBJECT_SYNC_VERSION.into(),
        type_digest: deployment.type_digest.clone(),
        current_cursor: current.into(),
        proposed_next_cursor: round_cursor(round),
        idempotency_key: format!("{namespace}:battles:{round:06}"),
        batch_digest: String::new(),
        collected_at_ms: round as i64 + 1,
        records,
        delivery: None,
    };
    let invalid = |error| SoakError::Spec(format!("battle batch is invalid: {error:?}"));
    batch.batch_digest = batch.canonical_digest().map_err(invalid)?;
    batch.validate().map_err(invalid)?;
    Ok(SourceBatch {
        contract_version: batch.contract_version,
        namespace: batch.namespace,
        producer_identity: batch.producer_identity,
        source: batch.source,
        source_instance: batch.source_instance,
        family: batch.family,
        adapter_id: batch.adapter_id,
        adapter_version: batch.adapter_version,
        type_digest: batch.type_digest,
        current_cursor: batch.current_cursor,
        proposed_next_cursor: batch.proposed_next_cursor,
        idempotency_key: batch.idempotency_key,
        batch_digest: batch.batch_digest,
        collected_at_ms: batch.collected_at_ms,
        records: batch
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

fn round_cursor(round: usize) -> String {
    format!("round:{:06}", round + 1)
}

fn event_row(script: &GameScript, round: usize, event: &BattleEvent) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("round".into(), round.to_string()),
        ("fleet".into(), script.plan.objects[event.fleet].id.clone()),
        ("planet".into(), event.planet.clone()),
        ("ships_lost".into(), event.ships_lost.to_string()),
        ("outcome".into(), event.outcome.into()),
    ])
}

async fn connect(target: &str) -> Result<Client, SoakError> {
    connect_sekai(target)
        .await
        .map(SekaiServiceClient::new)
        .map_err(|error| SoakError::Connect(error.to_string()))
}

/// Play `script` against `target` (a Unix socket the local operator may
/// use) and measure it. Fails if any proposal is not applied, any batch is
/// not committed, or the statistics lineage breaks.
///
/// Each round, every bot proposes its order over its own connection, then
/// intake delivers the round's battles, then the statistics transform runs.
/// The paths interleave one call at a time: concurrent mutating calls race
/// the split-store pairing epoch on SQLite and fence the deployment, so
/// the harness measures each path's time under the mix instead.
pub async fn run(
    target: &str,
    script: &GameScript,
    hardware: HardwareProfile,
    recorded_at: String,
) -> Result<SoakReport, SoakError> {
    let mut operator = connect(target).await?;
    let deployment = setup(&mut operator, script).await?;
    let namespace = &script.plan.namespace;

    // Every request is built before the clock starts.
    let mut bots = Vec::with_capacity(script.spec.bots);
    for (proposals, token) in script.proposals().into_iter().zip(&deployment.bot_tokens) {
        bots.push((connect(target).await?, token, proposals.into_iter()));
    }
    let mut intake_client = connect(target).await?;
    let mut intake = Vec::with_capacity(script.spec.rounds);
    let mut cursor = String::new();
    for round in 0..script.spec.rounds {
        let batch = source_batch(script, &deployment, round, &cursor)?;
        let rows = script.events[round]
            .iter()
            .map(|event| Row {
                values: event_row(script, round, event)
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
            })
            .collect::<Vec<_>>();
        intake.push((batch, rows));
        cursor = round_cursor(round);
    }

    let mut action_latencies = Vec::with_capacity(script.orders.len());
    let mut intake_latencies = Vec::with_capacity(script.spec.rounds);
    let mut transform_latencies = Vec::with_capacity(script.spec.rounds);
    let mut applied = 0;
    let mut previous_run: Option<String> = None;
    let mut lineage_chained = true;
    let mut output_rows = 0;
    let started = Instant::now();
    for (batch, rows) in intake {
        for (client, token, proposals) in &mut bots {
            let Some(request) = proposals.next() else {
                continue;
            };
            let sent = Instant::now();
            let instance = client
                .submit_action_instance(bearer(token, request)?)
                .await
                .map_err(rpc("submit action"))?
                .into_inner()
                .instance;
            action_latencies.push(sent.elapsed());
            applied += usize::from(instance.is_some_and(|i| i.status == "admitted"));
        }

        let sent = Instant::now();
        let token = &deployment.producer_token;
        let status = intake_client
            .apply_source_batch(bearer(
                token,
                ApplySourceBatchRequest { batch: Some(batch) },
            )?)
            .await
            .map_err(rpc("apply battle batch"))?
            .into_inner()
            .result
            .and_then(|result| result.transaction)
            .map(|transaction| transaction.status)
            .unwrap_or_default();
        if status != "COMMITTED" {
            return Err(SoakError::Invariant(format!(
                "battle batch ended {status:?}, not COMMITTED"
            )));
        }
        intake_client
            .append_rows(bearer(
                token,
                AppendRowsRequest {
                    dataset_id: deployment.events_dataset.clone(),
                    rows,
                },
            )?)
            .await
            .map_err(rpc("append battle rows"))?;
        intake_latencies.push(sent.elapsed());

        let sent = Instant::now();
        let run = operator
            .run_governed_transform(RunGovernedTransformRequest {
                namespace: namespace.clone(),
                transform_id: STATS_TRANSFORM.into(),
                incremental: false,
            })
            .await
            .map_err(rpc("run statistics transform"))?
            .into_inner()
            .run
            .ok_or_else(|| SoakError::Invariant("statistics run missing".into()))?;
        transform_latencies.push(sent.elapsed());
        if run.quarantined {
            return Err(SoakError::Invariant(format!(
                "statistics run quarantined: {}",
                run.quality_rule
            )));
        }
        if let Some(parent) = &previous_run {
            lineage_chained &= run.lineage_parent == *parent;
        }
        previous_run = Some(run.run_id);
        output_rows = run.rows_out;
    }
    let wall = started.elapsed();

    let proposed = script.orders.len();
    if applied != proposed {
        return Err(SoakError::Invariant(format!(
            "{applied} of {proposed} proposed Actions were applied"
        )));
    }
    if !lineage_chained || output_rows <= 0 {
        return Err(SoakError::Invariant(format!(
            "statistics lineage chained: {lineage_chained}, output rows: {output_rows}"
        )));
    }
    let records = script.spec.rounds * script.spec.batch_records;
    let action_time: Duration = action_latencies.iter().sum();
    let intake_time: Duration = intake_latencies.iter().sum();
    Ok(SoakReport {
        contract_version: REPORT_VERSION,
        recorded_at,
        crate_version: env!("CARGO_PKG_VERSION"),
        hardware,
        workload: WorkloadSummary {
            seed: script.spec.seed,
            preset: script.spec.preset.name(),
            objects: script.plan.objects.len(),
            bots: script.spec.bots,
            rounds: script.spec.rounds,
            batch_records: script.spec.batch_records,
            action_digest: script.action_digest.clone(),
        },
        wall_seconds: round3(wall.as_secs_f64()),
        actions: ActionMetrics {
            proposed,
            applied,
            seconds: round3(action_time.as_secs_f64()),
            per_second: per_second(applied, action_time),
            latency: Latency::of(&action_latencies),
        },
        intake: IntakeMetrics {
            batches: intake_latencies.len(),
            records,
            seconds: round3(intake_time.as_secs_f64()),
            batches_per_second: per_second(intake_latencies.len(), intake_time),
            records_per_second: per_second(records, intake_time),
            latency: Latency::of(&intake_latencies),
        },
        transform: TransformMetrics {
            runs: transform_latencies.len(),
            lineage_chained,
            output_rows,
            latency: Latency::of(&transform_latencies),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(seed: u64) -> SoakSpec {
        SoakSpec {
            seed,
            preset: SizePreset::Demo,
            bots: 3,
            rounds: 5,
            batch_records: 4,
        }
    }

    #[test]
    fn the_same_seed_plays_the_same_action_sequence_in_any_namespace() {
        let first = script(&spec(11), "soak-a").unwrap();
        let again = script(&spec(11), "soak-b").unwrap();
        assert_eq!(first.orders, again.orders);
        assert_eq!(first.events, again.events);
        assert_eq!(first.action_digest, again.action_digest);
        assert_eq!(first.orders.len(), 15);
        assert_ne!(
            first.action_digest,
            script(&spec(12), "soak-a").unwrap().action_digest
        );
        // No two bots ever order the same fleet, so concurrent bots never
        // race on one object.
        let mut owner = HashMap::new();
        for order in &first.orders {
            assert_eq!(*owner.entry(order.fleet).or_insert(order.bot), order.bot);
            assert_eq!(first.plan.objects[order.fleet].kind, FLEET_KIND);
        }
    }

    #[test]
    fn an_unplayable_spec_is_refused() {
        let mut crowded = spec(1);
        crowded.bots = 1_000;
        assert!(matches!(script(&crowded, "soak"), Err(SoakError::Spec(_))));
        let mut oversized = spec(1);
        oversized.batch_records = MAX_SOURCE_BATCH_RECORDS + 1;
        assert!(matches!(
            script(&oversized, "soak"),
            Err(SoakError::Spec(_))
        ));
    }
}
