//! Relational snapshot rehearsal against a known-content fixture (#2358).
//!
//! The plane, connector runtime, discovery, registered descriptors, and
//! snapshot sync already exist. This module sequences them against one
//! fixture database and scores held rows against that fixture's compare
//! call. The fixture image, compose project, and HTTP live at the edge.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    ConnectorSource, ConnectorSourceSpec, EnsureTeamNamespaceRequest, GetSourceDiscoveryRequest,
    GetSourceRequest, GetSourceSyncStateRequest, ListFilter, ListObjectsRequest, PutSourceRequest,
    RegisterSourceTypeDescriptorRequest, RequestSourceDiscoveryRequest, SourceConfigValue,
    TickGovernedTransformsRequest, source_config_value,
};
use sekai_chisei::sekai::source_type_descriptor::{
    ProposedSourceTypeDescriptor, registered_source_id,
};
use sekai_source_sdk::{SourceDiscovery, object_id_for};
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;

/// Pinned fixture image the rehearsal starts. Not a product dependency.
pub const KEIKO_IMAGE: &str = "ghcr.io/sannrox/keiko:v0.1.0";
pub const SOURCE_TOKEN: &str = "postgres.table";
pub const NAMESPACE: &str = "ops";
pub const SYSTEM: &str = "keiko";
pub const DATABASE: &str = "erp";
pub const SCHEMA: &str = "public";
pub const CREDENTIAL_REF: &str = "ops/keiko-connector";
pub const PLACEMENT_ROLE: &str = "rehearsal";
/// Team grant. `local` is reserved for the insecure/UDS caller identity.
pub const TEAM_PRINCIPAL: &str = "rehearsal";
const SYNC_EVERY_MS: i64 = 60_000;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(120);
const SYNC_TIMEOUT: Duration = Duration::from_secs(14_400);
const LIST_PAGE: i32 = 1_000;
/// keiko hard-deletes one exception every 7th activity step.
pub const HARD_DELETE_EVERY: u32 = 7;

/// One fixture table the relational type snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    pub name: &'static str,
    pub record_kind: &'static str,
    pub columns: &'static [Column],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    pub kind: ColumnKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    Int,
    Text,
    Numeric,
}

/// The six fixture tables, in discovery order.
pub const TABLES: &[Table] = &[
    Table {
        name: "customers",
        record_kind: "Customer",
        columns: &[
            Column {
                name: "id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "name",
                kind: ColumnKind::Text,
            },
            Column {
                name: "city",
                kind: ColumnKind::Text,
            },
            Column {
                name: "deleted_at",
                kind: ColumnKind::Text,
            },
        ],
    },
    Table {
        name: "orders",
        record_kind: "Order",
        columns: &[
            Column {
                name: "id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "customer_id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "requested_delivery",
                kind: ColumnKind::Text,
            },
            Column {
                name: "value_eur",
                kind: ColumnKind::Numeric,
            },
        ],
    },
    Table {
        name: "shipments",
        record_kind: "Shipment",
        columns: &[
            Column {
                name: "id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "order_id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "carrier_id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "status",
                kind: ColumnKind::Text,
            },
            Column {
                name: "weight_kg",
                kind: ColumnKind::Numeric,
            },
        ],
    },
    Table {
        name: "stops",
        record_kind: "Stop",
        columns: &[
            Column {
                name: "id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "shipment_id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "city",
                kind: ColumnKind::Text,
            },
            Column {
                name: "planned_on",
                kind: ColumnKind::Text,
            },
        ],
    },
    Table {
        name: "exceptions",
        record_kind: "Exception",
        columns: &[
            Column {
                name: "id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "shipment_id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "reason",
                kind: ColumnKind::Text,
            },
            Column {
                name: "raised_on",
                kind: ColumnKind::Text,
            },
        ],
    },
    Table {
        name: "credits",
        record_kind: "Credit",
        columns: &[
            Column {
                name: "id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "customer_id",
                kind: ColumnKind::Int,
            },
            Column {
                name: "amount_eur",
                kind: ColumnKind::Numeric,
            },
        ],
    },
];

pub fn source_id(table: &Table) -> String {
    table.name.to_string()
}

pub fn source_instance(table: &Table) -> String {
    format!("{SYSTEM}/{DATABASE}/{SCHEMA}/{}", table.name)
}

/// ADR 0060 object id for one primary-key value on a registered descriptor.
pub fn object_id(
    descriptor: &ProposedSourceTypeDescriptor,
    table: &Table,
    key: &str,
) -> Result<String, String> {
    let source = registered_source_id(descriptor, &source_instance(table), key)?;
    Ok(object_id_for(&descriptor.digest, &source))
}

/// JSON value the fixture compare call wants for one cell.
pub fn cell_json(kind: ColumnKind, value: Option<&str>) -> serde_json::Value {
    match value {
        None | Some("") => serde_json::Value::Null,
        Some(text) => match kind {
            ColumnKind::Int => text
                .parse::<i64>()
                .map(serde_json::Value::from)
                .unwrap_or_else(|_| serde_json::Value::String(text.to_string())),
            ColumnKind::Numeric => serde_json::Value::String(text.to_string()),
            ColumnKind::Text => serde_json::Value::String(text.to_string()),
        },
    }
}

/// One JSON object for the fixture compare body.
pub fn compare_row(
    table: &Table,
    properties: &BTreeMap<String, String>,
) -> BTreeMap<String, serde_json::Value> {
    table
        .columns
        .iter()
        .map(|column| {
            (
                column.name.to_string(),
                cell_json(column.kind, properties.get(column.name).map(String::as_str)),
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScorecardDiff {
    pub id: i64,
    pub column: String,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub received: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScorecardExamples {
    #[serde(default)]
    pub missing: Vec<i64>,
    #[serde(default)]
    pub extra: Vec<i64>,
    #[serde(default)]
    pub different: Vec<ScorecardDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scorecard {
    pub table: String,
    pub step: i64,
    pub expected: i64,
    pub received: i64,
    pub missing: i64,
    pub extra: i64,
    pub different: i64,
    #[serde(default)]
    pub examples: ScorecardExamples,
}

impl Scorecard {
    pub fn differences(&self) -> i64 {
        self.missing + self.extra + self.different
    }
}

/// Activity steps at which keiko hard-deletes one exception.
pub fn hard_delete_steps(advance_steps: u32) -> Vec<u32> {
    (1..=advance_steps)
        .filter(|step| step % HARD_DELETE_EVERY == 0)
        .collect()
}

/// What a later compare said about rows keiko no longer holds.
pub fn hard_delete_observation(card: &Scorecard, advance_steps: u32) -> serde_json::Value {
    serde_json::json!({
        "table": card.table,
        "step": card.step,
        "advance_steps": advance_steps,
        "hard_delete_every": HARD_DELETE_EVERY,
        "hard_delete_steps": hard_delete_steps(advance_steps),
        "expected": card.expected,
        "received": card.received,
        "missing": card.missing,
        "extra": card.extra,
        "different": card.different,
        "extra_examples": card.examples.extra,
        "missing_examples": card.examples.missing,
        "held_rows_keiko_deleted": card.extra > 0,
        "missing_rows_keiko_still_has": card.missing > 0,
    })
}

/// First snapshot must match. A later re-read records hard-delete and
/// in-place update gaps instead of treating them as a failed rehearsal.
pub fn unexpected_differences(pass: ComparePass, card: &Scorecard) -> bool {
    match pass {
        ComparePass::Initial => card.differences() > 0,
        ComparePass::AfterAdvance => false,
    }
}

/// A later sync has finished when success moves past the previous one.
pub fn sync_caught_up(
    previous_success_ms: i64,
    last_success_at_ms: i64,
    last_failure: &str,
    last_failure_at_ms: i64,
) -> bool {
    last_success_at_ms > previous_success_ms
        && (last_failure.is_empty() || last_success_at_ms >= last_failure_at_ms)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparePass {
    Initial,
    AfterAdvance,
}

#[derive(Debug)]
pub struct Rehearsal {
    plane: String,
    keiko: String,
    keiko_ca: PathBuf,
    db_endpoint: String,
    out: PathBuf,
    advance_steps: u32,
    run_name: String,
    /// Grant the team namespace and exit, so the runtime can register
    /// before discovery is requested.
    ensure_only: bool,
}

impl Rehearsal {
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut plane = String::new();
        let mut keiko = String::new();
        let mut keiko_ca = PathBuf::new();
        let mut db_endpoint = String::new();
        let mut out = PathBuf::new();
        let mut advance_steps = 20u32;
        let mut run_name = String::new();
        let mut ensure_only = false;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .cloned()
                    .ok_or_else(|| format!("{arg} requires a value"))
            };
            match arg.as_str() {
                "--plane" => plane = value()?,
                "--keiko" => keiko = value()?,
                "--keiko-ca" => keiko_ca = PathBuf::from(value()?),
                "--db-endpoint" => db_endpoint = value()?,
                "--out" => out = PathBuf::from(value()?),
                "--run-name" => run_name = value()?,
                "--ensure-only" => ensure_only = true,
                "--advance-steps" => {
                    advance_steps = value()?
                        .parse()
                        .map_err(|_| "--advance-steps must be a number".to_string())?;
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        if plane.is_empty() {
            return Err(
                "usage: relational-snapshot-rehearsal --plane <url> [--ensure-only] --keiko <url> --keiko-ca <pem> --db-endpoint <host:port> --out <dir> [--advance-steps n] [--run-name name]"
                    .into(),
            );
        }
        if !ensure_only
            && (keiko.is_empty()
                || keiko_ca.as_os_str().is_empty()
                || db_endpoint.is_empty()
                || out.as_os_str().is_empty())
        {
            return Err(
                "usage: relational-snapshot-rehearsal --plane <url> --keiko <url> --keiko-ca <pem> --db-endpoint <host:port> --out <dir> [--advance-steps n] [--run-name name]"
                    .into(),
            );
        }
        if run_name.is_empty() {
            run_name = if advance_steps == 0 {
                "medium".into()
            } else {
                "initial".into()
            };
        }
        Ok(Self {
            plane,
            keiko,
            keiko_ca,
            db_endpoint,
            out,
            advance_steps,
            run_name,
            ensure_only,
        })
    }
}

async fn ensure_namespace(plane: &str) -> Result<(), String> {
    let mut client = connect(plane).await?;
    client
        .ensure_team_namespace(EnsureTeamNamespaceRequest {
            namespace: NAMESPACE.into(),
            principal: TEAM_PRINCIPAL.into(),
            role: "admin".into(),
        })
        .await
        .map_err(status)?;
    Ok(())
}

pub async fn run(rehearsal: Rehearsal) -> Result<(), String> {
    if rehearsal.ensure_only {
        return ensure_namespace(&rehearsal.plane).await;
    }
    std::fs::create_dir_all(&rehearsal.out).map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut client = connect(&rehearsal.plane).await?;
    client
        .ensure_team_namespace(EnsureTeamNamespaceRequest {
            namespace: NAMESPACE.into(),
            principal: TEAM_PRINCIPAL.into(),
            role: "admin".into(),
        })
        .await
        .map_err(status)?;
    let http = http_client(&rehearsal.keiko_ca)?;
    let mut cards = Vec::new();
    let mut descriptors = BTreeMap::new();
    let mut sync_ms = BTreeMap::new();
    for table in TABLES {
        let descriptor = discover_and_register(&mut client, table, &rehearsal.db_endpoint).await?;
        let sync_started = Instant::now();
        wait_for_sync(&mut client, table, &descriptor.digest, SYNC_EVERY_MS).await?;
        sync_ms.insert(table.name, sync_started.elapsed().as_millis() as u64);
        descriptors.insert(table.name, descriptor);
    }
    let truth = fixture_truth(&http, &rehearsal.keiko).await?;
    for table in TABLES {
        let _rows = expected_rows(&truth, table.name)?;
        let jsonl = export_held(&mut client, table).await?;
        let card = compare_table(&http, &rehearsal.keiko, table.name, &jsonl).await?;
        write_scorecard(&rehearsal.out, &rehearsal.run_name, &card)?;
        if unexpected_differences(ComparePass::Initial, &card) {
            return Err(format!(
                "{} compare for {} reported missing={} extra={} different={}",
                rehearsal.run_name, table.name, card.missing, card.extra, card.different
            ));
        }
        cards.push((rehearsal.run_name.as_str(), card));
    }
    let mut hard_deletes = None;
    if rehearsal.advance_steps > 0 {
        advance(&http, &rehearsal.keiko, rehearsal.advance_steps).await?;
        for table in TABLES {
            let descriptor = descriptors
                .get(table.name)
                .ok_or_else(|| format!("{} was not registered", table.name))?;
            wait_for_sync(
                &mut client,
                table,
                &descriptor.digest,
                SYNC_EVERY_MS + 1_000,
            )
            .await?;
            let jsonl = export_held(&mut client, table).await?;
            let card = compare_table(&http, &rehearsal.keiko, table.name, &jsonl).await?;
            write_scorecard(&rehearsal.out, "after-advance", &card)?;
            if table.name == "exceptions" {
                hard_deletes = Some(hard_delete_observation(&card, rehearsal.advance_steps));
                write_json(
                    &rehearsal.out.join("hard-deletes.json"),
                    hard_deletes.as_ref().expect("just set"),
                )?;
            }
            cards.push(("after-advance", card));
        }
    }
    let report = serde_json::json!({
        "keiko_image": KEIKO_IMAGE,
        "run_name": rehearsal.run_name,
        "advance_steps": rehearsal.advance_steps,
        "wall_ms": started.elapsed().as_millis() as u64,
        "sync_ms": sync_ms,
        "hard_deletes": hard_deletes,
        "scorecards": cards.iter().map(|(pass, card)| json_card(pass, card)).collect::<Vec<_>>(),
    });
    write_json(&rehearsal.out.join("report.json"), &report)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn json_card(pass: &str, card: &Scorecard) -> serde_json::Value {
    serde_json::json!({
        "pass": pass,
        "table": card.table,
        "step": card.step,
        "expected": card.expected,
        "received": card.received,
        "missing": card.missing,
        "extra": card.extra,
        "different": card.different,
        "examples": card.examples,
    })
}

async fn connect(plane: &str) -> Result<SekaiServiceClient<Channel>, String> {
    let channel = tonic::transport::Endpoint::from_shared(plane.to_string())
        .map_err(|error| error.to_string())?
        .connect()
        .await
        .map_err(|error| error.to_string())?;
    Ok(SekaiServiceClient::new(channel))
}

fn text_config(fields: &[(&str, &str)]) -> std::collections::HashMap<String, SourceConfigValue> {
    fields
        .iter()
        .map(|(name, value)| {
            (
                (*name).to_string(),
                SourceConfigValue {
                    value: Some(source_config_value::Value::Text((*value).to_string())),
                },
            )
        })
        .collect()
}

fn spec(
    table: &Table,
    db_endpoint: &str,
    type_digest: Option<&str>,
    every_ms: i64,
) -> ConnectorSourceSpec {
    let mut fields = vec![
        ("endpoint", db_endpoint),
        ("database", DATABASE),
        ("user", "connector"),
        ("table", table.name),
        ("record_kind", table.record_kind),
        ("pk_columns", "id"),
        ("monotonic_column", "id"),
        ("display_column", "id"),
    ];
    if let Some(digest) = type_digest {
        fields.push(("type_digest", digest));
    }
    ConnectorSourceSpec {
        connector_type: "relational".into(),
        connector_version: "1".into(),
        config: text_config(&fields),
        credential_ref: CREDENTIAL_REF.into(),
        egress: vec![db_endpoint.to_string()],
        placement: [("role".into(), PLACEMENT_ROLE.into())].into(),
        every_ms,
        owner: "local".into(),
        markings: Vec::new(),
        certification_id: String::new(),
    }
}

async fn put_source(
    client: &mut SekaiServiceClient<Channel>,
    table: &Table,
    spec: ConnectorSourceSpec,
    expected_revision: i64,
) -> Result<ConnectorSource, String> {
    let response = client
        .put_source(PutSourceRequest {
            namespace: NAMESPACE.into(),
            source_id: source_id(table),
            source: SOURCE_TOKEN.into(),
            source_instance: source_instance(table),
            spec: Some(spec),
            expected_revision,
        })
        .await
        .map_err(status)?;
    response
        .into_inner()
        .source
        .ok_or_else(|| "put source returned no source".to_string())
}

async fn discover_and_register(
    client: &mut SekaiServiceClient<Channel>,
    table: &Table,
    db_endpoint: &str,
) -> Result<ProposedSourceTypeDescriptor, String> {
    let created = put_source(client, table, spec(table, db_endpoint, None, 0), 0).await?;
    let discovery_id = client
        .request_source_discovery(RequestSourceDiscoveryRequest {
            namespace: NAMESPACE.into(),
            source_id: source_id(table),
        })
        .await
        .map_err(status)?
        .into_inner()
        .discovery
        .ok_or("discovery request returned nothing")?
        .discovery_id;
    let discovery = wait_for_discovery(client, &discovery_id).await?;
    let kind = discovery
        .record_kinds
        .iter()
        .find(|kind| kind.record_kind == table.record_kind)
        .ok_or_else(|| format!("discovery omitted {}", table.record_kind))?;
    let registered = client
        .register_source_type_descriptor(RegisterSourceTypeDescriptorRequest {
            namespace: NAMESPACE.into(),
            source: SOURCE_TOKEN.into(),
            record_kind: kind.record_kind.clone(),
            schema_revision: kind.schema_revision.clone(),
        })
        .await
        .map_err(status)?
        .into_inner()
        .descriptor
        .ok_or("register descriptor returned nothing")?;
    let descriptor = ProposedSourceTypeDescriptor::prepare(
        registered.source,
        registered.record_kind,
        registered.schema_revision,
    )?;
    if descriptor.digest != registered.digest {
        return Err("registered digest does not match the prepared identity".into());
    }
    put_source(
        client,
        table,
        spec(table, db_endpoint, Some(&descriptor.digest), SYNC_EVERY_MS),
        created.revision,
    )
    .await?;
    Ok(descriptor)
}

async fn wait_for_discovery(
    client: &mut SekaiServiceClient<Channel>,
    discovery_id: &str,
) -> Result<SourceDiscovery, String> {
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    loop {
        let result = client
            .get_source_discovery(GetSourceDiscoveryRequest {
                namespace: NAMESPACE.into(),
                discovery_id: discovery_id.into(),
            })
            .await
            .map_err(status)?
            .into_inner()
            .discovery
            .ok_or("discovery result missing")?;
        match result.status.as_str() {
            "completed" => {
                return serde_json::from_str(&result.discovery_json)
                    .map_err(|error| format!("discovery json: {error}"));
            }
            "failed" => {
                return Err(format!(
                    "discovery failed as {}",
                    if result.failure.is_empty() {
                        "unknown"
                    } else {
                        &result.failure
                    }
                ));
            }
            _ if Instant::now() >= deadline => {
                return Err(format!(
                    "discovery still {} after {}s",
                    result.status,
                    DISCOVERY_TIMEOUT.as_secs()
                ));
            }
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

async fn wait_for_sync(
    client: &mut SekaiServiceClient<Channel>,
    table: &Table,
    type_digest: &str,
    every_ms: i64,
) -> Result<(), String> {
    let source = client
        .get_source(GetSourceRequest {
            namespace: NAMESPACE.into(),
            source_id: source_id(table),
        })
        .await
        .map_err(status)?
        .into_inner()
        .source
        .ok_or("source missing")?;
    let previous_success_ms = source
        .sync
        .as_ref()
        .map(|sync| sync.last_success_at_ms)
        .unwrap_or(0);
    let mut spec = source.spec.ok_or("source has no spec")?;
    spec.every_ms = every_ms;
    put_source(client, table, spec, source.revision).await?;
    tick(client).await?;
    let deadline = Instant::now() + SYNC_TIMEOUT;
    let mut last_failure = String::new();
    loop {
        let listed = client
            .get_source(GetSourceRequest {
                namespace: NAMESPACE.into(),
                source_id: source_id(table),
            })
            .await
            .map_err(status)?
            .into_inner()
            .source
            .ok_or("source missing")?;
        if let Some(sync) = listed.sync.as_ref() {
            if !sync.last_failure.is_empty() {
                last_failure.clone_from(&sync.last_failure);
            }
            if sync_caught_up(
                previous_success_ms,
                sync.last_success_at_ms,
                &sync.last_failure,
                sync.last_failure_at_ms,
            ) {
                let state = client
                    .get_source_sync_state(GetSourceSyncStateRequest {
                        namespace: NAMESPACE.into(),
                        source_instance: source_instance(table),
                        type_digest: type_digest.into(),
                    })
                    .await
                    .map_err(status)?
                    .into_inner();
                if state.found {
                    return Ok(());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "sync of {} did not finish; last_failure={last_failure}",
                table.name
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        tick(client).await?;
    }
}

async fn tick(client: &mut SekaiServiceClient<Channel>) -> Result<(), String> {
    client
        .tick_governed_transforms(TickGovernedTransformsRequest { now_ms: 0 })
        .await
        .map_err(status)?;
    Ok(())
}

async fn export_held(
    client: &mut SekaiServiceClient<Channel>,
    table: &Table,
) -> Result<String, String> {
    let mut lines = Vec::new();
    let mut page_token = String::new();
    loop {
        let listed = client
            .list_objects(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: table.record_kind.into(),
                    namespace: NAMESPACE.into(),
                    limit: LIST_PAGE,
                    ..Default::default()
                }),
                page_token,
            })
            .await
            .map_err(status)?
            .into_inner();
        for object in listed.objects {
            let properties = object.properties.into_iter().collect();
            let row = compare_row(table, &properties);
            lines.push(serde_json::to_string(&row).map_err(|error| error.to_string())?);
        }
        if listed.next_page_token.is_empty() {
            break;
        }
        page_token = listed.next_page_token;
    }
    Ok(lines.join("\n"))
}

fn http_client(ca: &Path) -> Result<reqwest::Client, String> {
    let pem = std::fs::read(ca).map_err(|error| format!("read CA: {error}"))?;
    let cert =
        reqwest::Certificate::from_pem(&pem).map_err(|error| format!("parse CA: {error}"))?;
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .https_only(true)
        .build()
        .map_err(|error| error.to_string())
}

#[derive(Debug, Deserialize)]
struct Truth {
    erp: TruthErp,
}

#[derive(Debug, Deserialize)]
struct TruthErp {
    tables: BTreeMap<String, TruthTable>,
}

#[derive(Debug, Deserialize)]
struct TruthTable {
    rows: i64,
}

async fn fixture_truth(http: &reqwest::Client, keiko: &str) -> Result<Truth, String> {
    let response = http
        .get(format!("{keiko}/truth"))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("truth HTTP {}", response.status()));
    }
    response.json().await.map_err(|error| error.to_string())
}

fn expected_rows(truth: &Truth, table: &str) -> Result<i64, String> {
    truth
        .erp
        .tables
        .get(table)
        .map(|table| table.rows)
        .ok_or_else(|| format!("truth omitted {table}"))
}

async fn compare_table(
    http: &reqwest::Client,
    keiko: &str,
    table: &str,
    jsonl: &str,
) -> Result<Scorecard, String> {
    let response = http
        .post(format!("{keiko}/truth/compare/{table}"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
        .body(jsonl.to_string())
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("compare {table} HTTP {}", response.status()));
    }
    response.json().await.map_err(|error| error.to_string())
}

async fn advance(http: &reqwest::Client, keiko: &str, steps: u32) -> Result<(), String> {
    let response = http
        .post(format!("{keiko}/control/advance"))
        .json(&serde_json::json!({ "steps": steps }))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("advance HTTP {}", response.status()));
    }
    Ok(())
}

fn write_scorecard(out: &Path, pass: &str, card: &Scorecard) -> Result<(), String> {
    write_json(&out.join(format!("{pass}-{}.json", card.table)), card)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn status(error: tonic::Status) -> String {
    format!("{}: {}", error.code(), error.message())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_grant_is_not_a_reserved_principal() {
        assert!(!matches!(TEAM_PRINCIPAL, "local" | "root" | "anonymous"));
    }

    #[test]
    fn six_tables_cover_the_fixture() {
        let names: Vec<_> = TABLES.iter().map(|table| table.name).collect();
        assert_eq!(
            names,
            [
                "customers",
                "orders",
                "shipments",
                "stops",
                "exceptions",
                "credits"
            ]
        );
    }

    #[test]
    fn instance_token_follows_adr_0100() {
        assert_eq!(source_instance(&TABLES[0]), "keiko/erp/public/customers");
    }

    #[test]
    fn compare_row_coerces_numbers_and_nulls() {
        let mut properties = BTreeMap::new();
        properties.insert("id".into(), "1".into());
        properties.insert("name".into(), "Kontor Hamburg 1".into());
        properties.insert("city".into(), "Hamburg".into());
        let row = compare_row(&TABLES[0], &properties);
        assert_eq!(row.get("id"), Some(&serde_json::json!(1)));
        assert_eq!(row.get("deleted_at"), Some(&serde_json::Value::Null));
        assert_eq!(row.get("city"), Some(&serde_json::json!("Hamburg")));
        let mut order = BTreeMap::new();
        order.insert("id".into(), "1".into());
        order.insert("customer_id".into(), "2".into());
        order.insert("requested_delivery".into(), "2026-03-14".into());
        order.insert("value_eur".into(), "2247.80".into());
        let order_row = compare_row(&TABLES[1], &order);
        assert_eq!(
            order_row.get("value_eur"),
            Some(&serde_json::json!("2247.80"))
        );
    }

    #[test]
    fn initial_scorecard_differences_are_unexpected() {
        let clean = Scorecard {
            table: "customers".into(),
            step: 0,
            expected: 200,
            received: 200,
            missing: 0,
            extra: 0,
            different: 0,
            examples: ScorecardExamples::default(),
        };
        let drifted = Scorecard {
            different: 1,
            ..clean.clone()
        };
        assert!(!unexpected_differences(ComparePass::Initial, &clean));
        assert!(unexpected_differences(ComparePass::Initial, &drifted));
        assert!(!unexpected_differences(ComparePass::AfterAdvance, &drifted));
    }

    #[test]
    fn hard_delete_observation_records_extras_without_assuming() {
        assert_eq!(hard_delete_steps(20), vec![7, 14]);
        let card = Scorecard {
            table: "exceptions".into(),
            step: 20,
            expected: 1000,
            received: 1002,
            missing: 2,
            extra: 2,
            different: 0,
            examples: ScorecardExamples {
                extra: vec![1, 2],
                missing: vec![1001, 1002],
                ..ScorecardExamples::default()
            },
        };
        let observed = hard_delete_observation(&card, 20);
        assert_eq!(observed["held_rows_keiko_deleted"], true);
        assert_eq!(observed["extra"], 2);
        assert_eq!(observed["extra_examples"], serde_json::json!([1, 2]));
        let clean = Scorecard {
            extra: 0,
            missing: 0,
            received: 1000,
            examples: ScorecardExamples::default(),
            ..card
        };
        assert_eq!(
            hard_delete_observation(&clean, 20)["held_rows_keiko_deleted"],
            false
        );
    }

    #[test]
    fn a_later_sync_needs_a_newer_success() {
        assert!(!sync_caught_up(10, 10, "", 0));
        assert!(sync_caught_up(10, 11, "", 0));
        assert!(!sync_caught_up(10, 11, "invalid", 12));
        assert!(sync_caught_up(10, 13, "invalid", 12));
    }

    #[test]
    fn object_id_is_the_registered_identity() {
        let descriptor =
            ProposedSourceTypeDescriptor::prepare(SOURCE_TOKEN, "Customer", "rev1").unwrap();
        let id = object_id(&descriptor, &TABLES[0], "1").unwrap();
        let source = registered_source_id(&descriptor, "keiko/erp/public/customers", "1").unwrap();
        assert_eq!(id, object_id_for(&descriptor.digest, &source));
        assert!(id.starts_with("sync-"));
    }

    #[test]
    fn from_args_requires_the_edge_flags() {
        let err = Rehearsal::from_args(&[]).unwrap_err();
        assert!(err.contains("--plane"));
        let rehearsal = Rehearsal::from_args(&[
            "--plane".into(),
            "http://127.0.0.1:9".into(),
            "--keiko".into(),
            "https://127.0.0.1:8".into(),
            "--keiko-ca".into(),
            "ca.crt".into(),
            "--db-endpoint".into(),
            "127.0.0.1:5432".into(),
            "--out".into(),
            "out".into(),
        ])
        .unwrap();
        assert_eq!(rehearsal.advance_steps, 20);
        assert_eq!(rehearsal.run_name, "initial");
        let medium = Rehearsal::from_args(&[
            "--plane".into(),
            "http://127.0.0.1:9".into(),
            "--keiko".into(),
            "https://127.0.0.1:8".into(),
            "--keiko-ca".into(),
            "ca.crt".into(),
            "--db-endpoint".into(),
            "127.0.0.1:5432".into(),
            "--out".into(),
            "out".into(),
            "--advance-steps".into(),
            "0".into(),
            "--run-name".into(),
            "medium".into(),
        ])
        .unwrap();
        assert_eq!(medium.advance_steps, 0);
        assert_eq!(medium.run_name, "medium");
        let ensure = Rehearsal::from_args(&[
            "--plane".into(),
            "http://127.0.0.1:9".into(),
            "--ensure-only".into(),
        ])
        .unwrap();
        assert!(ensure.ensure_only);
    }
}
