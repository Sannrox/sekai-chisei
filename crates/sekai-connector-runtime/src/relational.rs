//! The `relational` connector type, over PostgreSQL: snapshot pages from
//! one table, a reachability check, and saved-export delivery into the
//! Source's `delivery_table`.
//!
//! Pages follow a plane-owned opaque cursor (ADR 0022, ADR 0100). Rows are
//! ordered by a monotonic column, then the primary key. Each page starts
//! after the last `(monotonic, key)` a committed page ended on, so a
//! runtime that dies mid-snapshot loses nothing and applies no row twice.
//! A short page completes the scan; later syncs read rows whose monotonic
//! value is greater, including updates of already-synced keys. A change
//! that does not increase the monotonic value stays behind the committed
//! tuple; ordered change capture is a later profile. Tables without a
//! primary key, and NULL key or monotonic cells, fail closed.
//! Each row's `external_id` is the ADR 0100 encoding of its primary-key
//! columns. Restricted column names never leave as properties.
//!
//! Each delivery is one row keyed by its receipt, inserted with
//! `ON CONFLICT (receipt_id) DO NOTHING`. A redelivery after a crash or a
//! takeover therefore writes nothing twice. A row already present for the
//! receipt with different content fails the delivery as invalid rather
//! than being overwritten. The table needs the columns `receipt_id` (unique
//! text), `namespace`, `definition_id`, `content_digest` (text) and
//! `content` (bytea).
//!
//! The connection always uses TLS and verifies the server's certificate
//! against the system roots plus an optional operator CA. It goes to the
//! `endpoint` the egress allowlist admitted, parsed the same way. When the
//! endpoint's name resolves to several addresses, a failure reports the
//! last one tried, so an endpoint is best named by one address.

use std::collections::BTreeMap;
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use native_tls::{Certificate, TlsConnector};
use postgres::config::SslMode;
use postgres::error::SqlState;
use postgres::types::{IsNull, ToSql, Type, to_sql_checked};
use postgres_native_tls::MakeTlsConnector;
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, Destination, ExportArtifact,
    MAX_SOURCE_DISPLAY_NAME_BYTES, PropertyValue, SnapshotPage, SnapshotRead, SourceRecord,
    column_name_suggests_sensitive, contains_secret_like_text,
};
use sha2::{Digest, Sha256};

use crate::sync::Prepared;

/// The PostgreSQL port an endpoint without one connects to.
const DEFAULT_PORT: u16 = 5432;

/// ADR 0100 source token stamped on connector-local records.
const SOURCE_POSTGRES_TABLE: &str = "postgres.table";

/// How long one connection or statement may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// One database, reached as the Source's user with its bound password.
pub struct Relational {
    config: postgres::Config,
    tls: MakeTlsConnector,
    /// The quoted, validated delivery table, when the Source names one.
    delivery_table: Option<String>,
    source: String,
    source_instance: String,
    fields: sekai_source_sdk::SourceConfig,
}

/// The TLS connector every relational Source connects with: the system
/// roots, plus `ca_pem` when the operator trusts a private CA.
pub fn tls(ca_pem: Option<&[u8]>) -> Result<MakeTlsConnector, String> {
    let mut builder = TlsConnector::builder();
    if let Some(pem) = ca_pem {
        let certificate =
            Certificate::from_pem(pem).map_err(|error| format!("parse CA certificate: {error}"))?;
        builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map(MakeTlsConnector::new)
        .map_err(|error| format!("build TLS connector: {error}"))
}

/// Opens the relational type for a prepared Source; register it with
/// `Connectors::with(&RELATIONAL_CONNECTOR, move |prepared| relational::open(prepared, &tls))`.
pub fn open(
    prepared: &Prepared,
    tls: &MakeTlsConnector,
) -> Result<Box<dyn Connector + Send>, ConnectorFailure> {
    let text = |name: &str| match prepared.config.get(name) {
        Some(ConfigValue::Text(value)) => Ok(Some(value.as_str())),
        None => Ok(None),
        Some(_) => Err(ConnectorFailure::Invalid),
    };
    let required = |name: &str| text(name)?.ok_or(ConnectorFailure::Invalid);
    let endpoint = Destination::parse(required("endpoint")?).ok_or(ConnectorFailure::Invalid)?;
    let password = prepared
        .credentials
        .get("password")
        .ok_or(ConnectorFailure::AuthFailed)?;
    let mut config = postgres::Config::new();
    config
        .host(&endpoint.host)
        .port(endpoint.port.unwrap_or(DEFAULT_PORT))
        .dbname(required("database")?)
        .user(required("user")?)
        .password(password.expose())
        .ssl_mode(SslMode::Require)
        .connect_timeout(TIMEOUT)
        // A locked table or a half-open connection ends an attempt rather
        // than pinning its thread past the claim.
        .options(&format!("-c statement_timeout={}", TIMEOUT.as_millis()))
        .keepalives_idle(TIMEOUT)
        .tcp_user_timeout(TIMEOUT)
        .application_name("sekai-connector-runtime");
    let delivery_table = text("delivery_table")?
        .map(|table| quoted_table(table).ok_or(ConnectorFailure::Invalid))
        .transpose()?;
    Ok(Box::new(Relational {
        config,
        tls: tls.clone(),
        delivery_table,
        source: SOURCE_POSTGRES_TABLE.into(),
        source_instance: prepared.source_instance.clone(),
        fields: prepared.config.clone(),
    }))
}

impl Relational {
    fn connect(&self) -> Result<postgres::Client, ConnectorFailure> {
        self.config.connect(self.tls.clone()).map_err(failure)
    }
}

impl Connector for Relational {
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        self.connect()?.simple_query("SELECT 1").map_err(failure)?;
        Ok(())
    }

    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        let spec = ReadSpec::parse(&self.fields)?;
        let per_page = max_records.clamp(1, sekai_source_sdk::MAX_SOURCE_BATCH_RECORDS);
        let cursor = committed_cursor.and_then(Cursor::parse).unwrap_or_default();
        let after = cursor.after();
        let sql = spec.select_sql(after.is_some(), per_page);
        let mut client = self.connect()?;
        let actual_pk = relation_pk(&mut client, &spec.table)?;
        if !primary_key_matches(&spec.pk_names, &actual_pk) {
            return Err(ConnectorFailure::Invalid);
        }
        require_not_null_order(&mut client, &spec.table, &spec.order_names)?;
        let rows = query_after(&mut client, &sql, after.as_deref())?;
        let fetched = rows
            .iter()
            .map(MemRow::from_postgres)
            .collect::<Result<Vec<_>, _>>()?;
        page_of(
            &spec,
            &self.source,
            &self.source_instance,
            &fetched,
            committed_cursor,
            per_page,
            now_ms(),
        )
    }

    fn deliver(&mut self, artifact: &ExportArtifact<'_>) -> Result<(), ConnectorFailure> {
        let table = self
            .delivery_table
            .as_deref()
            .ok_or(ConnectorFailure::Invalid)?;
        let mut client = self.connect()?;
        let inserted = client
            .execute(
                &format!(
                    "INSERT INTO {table} \
                     (receipt_id, namespace, definition_id, content_digest, content) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (receipt_id) DO NOTHING"
                ),
                &[
                    &artifact.receipt_id,
                    &artifact.namespace,
                    &artifact.definition_id,
                    &artifact.content_digest,
                    &artifact.bytes,
                ],
            )
            .map_err(failure)?;
        if inserted == 1 {
            return Ok(());
        }
        // Delivered before: the same content is a replay, other content is
        // a conflict the operator resolves.
        let present: String = client
            .query_one(
                &format!("SELECT content_digest FROM {table} WHERE receipt_id = $1"),
                &[&artifact.receipt_id],
            )
            .map_err(failure)?
            .get(0);
        if present == artifact.content_digest {
            Ok(())
        } else {
            Err(ConnectorFailure::Invalid)
        }
    }
}

/// Snapshot-page configuration taken from the Source. Delivery-only
/// Sources omit it and fail here rather than inventing a table.
struct ReadSpec {
    table: String,
    record_kind: String,
    pk_names: Vec<String>,
    order_names: Vec<String>,
    order_sql: Vec<String>,
    display_name: String,
    version_name: String,
}

impl ReadSpec {
    fn parse(config: &sekai_source_sdk::SourceConfig) -> Result<Self, ConnectorFailure> {
        let text = |name: &str| match config.get(name) {
            Some(ConfigValue::Text(value)) => Ok(value.as_str()),
            _ => Err(ConnectorFailure::Invalid),
        };
        let table = quoted_table(text("table")?).ok_or(ConnectorFailure::Invalid)?;
        let record_kind = text("record_kind")?;
        if !registered_token(record_kind) {
            return Err(ConnectorFailure::Invalid);
        }
        let pk_names = column_list(text("pk_columns")?)?;
        if pk_names.is_empty()
            || pk_names
                .iter()
                .any(|name| column_name_suggests_sensitive(name))
        {
            return Err(ConnectorFailure::Invalid);
        }
        let monotonic = column_name(text("monotonic_column")?)?;
        if column_name_suggests_sensitive(&monotonic) {
            return Err(ConnectorFailure::Invalid);
        }
        let display_name = match config.get("display_column") {
            Some(ConfigValue::Text(value)) => column_name(value)?,
            None => pk_names[0].clone(),
            Some(_) => return Err(ConnectorFailure::Invalid),
        };
        let version_name = match config.get("version_column") {
            Some(ConfigValue::Text(value)) => column_name(value)?,
            None => monotonic.clone(),
            Some(_) => return Err(ConnectorFailure::Invalid),
        };
        if column_name_suggests_sensitive(&display_name)
            || column_name_suggests_sensitive(&version_name)
        {
            return Err(ConnectorFailure::Invalid);
        }
        let mut order_names = vec![monotonic];
        for name in &pk_names {
            if !order_names.contains(name) {
                order_names.push(name.clone());
            }
        }
        if order_names.len() > 8 {
            return Err(ConnectorFailure::Invalid);
        }
        let order_sql = order_names
            .iter()
            .map(|name| quoted_ident(name).ok_or(ConnectorFailure::Invalid))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            table,
            record_kind: record_kind.to_string(),
            pk_names,
            order_names,
            order_sql,
            display_name,
            version_name,
        })
    }

    fn select_sql(&self, after: bool, limit: usize) -> String {
        let order = self.order_sql.join(", ");
        let mut sql = format!("SELECT * FROM {} ", self.table);
        if after {
            let params = (1..=self.order_sql.len())
                .map(|index| format!("${index}"))
                .collect::<Vec<_>>()
                .join(", ");
            sql.push_str(&format!("WHERE ({order}) > ({params}) "));
        }
        sql.push_str(&format!("ORDER BY {order} LIMIT {limit}"));
        sql
    }
}

/// One fetched row, keyed by folded column name.
#[derive(Debug, Clone)]
struct MemRow {
    cells: BTreeMap<String, Cell>,
}

impl MemRow {
    fn from_postgres(row: &postgres::Row) -> Result<Self, ConnectorFailure> {
        let mut cells = BTreeMap::new();
        for (idx, column) in row.columns().iter().enumerate() {
            let name = column.name().to_ascii_lowercase();
            if column_name_suggests_sensitive(&name) {
                continue;
            }
            if let Some(cell) = cell_from(row, idx)? {
                insert_cell(&mut cells, name, cell)?;
            }
        }
        Ok(Self { cells })
    }

    fn order(&self, spec: &ReadSpec) -> Result<Vec<Cell>, ConnectorFailure> {
        spec.order_names
            .iter()
            .map(|name| {
                self.cells
                    .get(name)
                    .cloned()
                    .ok_or(ConnectorFailure::Invalid)
            })
            .collect()
    }
}

fn page_of(
    spec: &ReadSpec,
    source: &str,
    source_instance: &str,
    fetched: &[MemRow],
    committed_cursor: Option<&str>,
    max_records: usize,
    now_ms: i64,
) -> Result<SnapshotRead, ConnectorFailure> {
    if fetched.is_empty() {
        return if committed_cursor.is_some() {
            Ok(SnapshotRead::Complete)
        } else {
            Ok(SnapshotRead::Page(SnapshotPage {
                records: Vec::new(),
                proposed_next_cursor: Cursor {
                    after: Vec::new(),
                    settled: true,
                }
                .to_string(),
                collected_at_ms: now_ms,
                complete: true,
            }))
        };
    }
    let complete = fetched.len() < max_records;
    let last = fetched
        .last()
        .ok_or(ConnectorFailure::Invalid)?
        .order(spec)?;
    let records = fetched
        .iter()
        .map(|row| record(spec, source, source_instance, row, now_ms))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SnapshotRead::Page(SnapshotPage {
        records,
        proposed_next_cursor: Cursor {
            after: last,
            settled: complete,
        }
        .to_string(),
        collected_at_ms: now_ms,
        complete,
    }))
}

fn record(
    spec: &ReadSpec,
    source: &str,
    source_instance: &str,
    row: &MemRow,
    now_ms: i64,
) -> Result<SourceRecord, ConnectorFailure> {
    let mut properties = BTreeMap::new();
    for (name, cell) in &row.cells {
        if column_name_suggests_sensitive(name) {
            continue;
        }
        properties.insert(name.clone(), cell.property());
    }
    let pk = spec
        .pk_names
        .iter()
        .map(|name| row.cells.get(name).ok_or(ConnectorFailure::Invalid))
        .collect::<Result<Vec<_>, _>>()?;
    let external_id = encode_key(&pk)?;
    let version = row
        .cells
        .get(&spec.version_name)
        .ok_or(ConnectorFailure::Invalid)?
        .as_text();
    if version.is_empty() || contains_secret_like_text(&version) {
        return Err(ConnectorFailure::Invalid);
    }
    let mut display_name = if column_name_suggests_sensitive(&spec.display_name) {
        external_id.clone()
    } else {
        row.cells
            .get(&spec.display_name)
            .map(Cell::as_text)
            .filter(|value| !value.is_empty() && !contains_secret_like_text(value))
            .unwrap_or_else(|| external_id.clone())
    };
    while display_name.len() > MAX_SOURCE_DISPLAY_NAME_BYTES {
        display_name.pop();
    }
    if display_name.trim().is_empty() {
        display_name = external_id.clone();
    }
    Ok(SourceRecord {
        source: source.into(),
        source_instance: source_instance.into(),
        external_id,
        source_version: version,
        type_name: spec.record_kind.clone(),
        display_name,
        payload_digest: digest_of(&properties),
        properties,
        deleted: false,
        observed_at_ms: now_ms,
        source_sequence: None,
    })
}

fn digest_of(properties: &BTreeMap<String, PropertyValue>) -> String {
    let cells: BTreeMap<&str, String> = properties
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_cell()))
        .collect();
    let canonical = serde_json::to_vec(&cells).unwrap_or_else(|_| b"{}".to_vec());
    format!("sha256:{:x}", Sha256::digest(canonical))
}

fn encode_key(cells: &[&Cell]) -> Result<String, ConnectorFailure> {
    let mut parts = Vec::with_capacity(cells.len());
    for cell in cells {
        let text = cell.as_text();
        if text.is_empty() {
            return Err(ConnectorFailure::Invalid);
        }
        parts.push(percent_encode(&text));
    }
    Ok(parts.join("~"))
}

fn query_after(
    client: &mut postgres::Client,
    sql: &str,
    after: Option<&[Cell]>,
) -> Result<Vec<postgres::Row>, ConnectorFailure> {
    let Some(after) = after else {
        return client.query(sql, &[]).map_err(failure);
    };
    if after.len() > 8 {
        return Err(ConnectorFailure::Invalid);
    }
    let params: Vec<&(dyn ToSql + Sync)> = after.iter().map(|cell| cell as _).collect();
    client.query(sql, &params).map_err(failure)
}

/// The relation's primary-key column names, folded as PostgreSQL folds
/// unquoted identifiers, in index order. No primary key is invalid.
fn relation_pk(
    client: &mut postgres::Client,
    table: &str,
) -> Result<Vec<String>, ConnectorFailure> {
    let name = relation_name(table);
    let rows = client
        .query(
            "SELECT a.attname \
             FROM pg_index i \
             JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true \
             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum \
             WHERE i.indrelid = $1::text::regclass AND i.indisprimary \
               AND k.ord <= i.indnkeyatts \
             ORDER BY k.ord",
            &[&name],
        )
        .map_err(failure)?;
    if rows.is_empty() {
        return Err(ConnectorFailure::Invalid);
    }
    Ok(rows
        .iter()
        .map(|row| {
            let name: String = row.get(0);
            name.to_ascii_lowercase()
        })
        .collect())
}

fn primary_key_matches(configured: &[String], actual: &[String]) -> bool {
    configured == actual
}

/// NULL order cells sort last and compare as unknown, so a resume would
/// skip them forever. The columns that form the cursor must be NOT NULL.
fn require_not_null_order(
    client: &mut postgres::Client,
    table: &str,
    columns: &[String],
) -> Result<(), ConnectorFailure> {
    let name = relation_name(table);
    let columns = columns.to_vec();
    let rows = client
        .query(
            "SELECT a.attname \
             FROM pg_attribute a \
             WHERE a.attrelid = $1::text::regclass \
               AND NOT a.attisdropped \
               AND a.attnotnull \
               AND a.attname = ANY($2::text[])",
            &[&name, &columns],
        )
        .map_err(failure)?;
    let found: Vec<String> = rows
        .iter()
        .map(|row| {
            let attname: String = row.get(0);
            attname.to_ascii_lowercase()
        })
        .collect();
    if columns.iter().any(|column| !found.contains(column)) {
        Err(ConnectorFailure::Invalid)
    } else {
        Ok(())
    }
}

/// Quoted `"schema"."table"` as the `regclass` text PostgreSQL expects.
fn relation_name(quoted: &str) -> String {
    quoted.replace('"', "")
}

fn system_time_micros(time: SystemTime) -> Option<i64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_micros()).ok(),
        Err(error) => i64::try_from(error.duration().as_micros())
            .ok()
            .map(i64::saturating_neg),
    }
}

fn system_time_from_micros(us: i64) -> Result<SystemTime, Box<dyn Error + Sync + Send>> {
    let duration = Duration::from_micros(us.unsigned_abs());
    Ok(if us >= 0 {
        UNIX_EPOCH + duration
    } else {
        UNIX_EPOCH
            .checked_sub(duration)
            .ok_or("timestamp before epoch")?
    })
}

fn insert_cell(
    cells: &mut BTreeMap<String, Cell>,
    name: String,
    cell: Cell,
) -> Result<(), ConnectorFailure> {
    if cells.contains_key(&name) {
        return Err(ConnectorFailure::Invalid);
    }
    cells.insert(name, cell);
    Ok(())
}

fn cell_from(row: &postgres::Row, idx: usize) -> Result<Option<Cell>, ConnectorFailure> {
    let ty = row.columns()[idx].type_();
    let get = |value: Result<Option<Cell>, postgres::Error>| match value {
        Ok(value) => Ok(value),
        Err(_) => Err(ConnectorFailure::Invalid),
    };
    if *ty == Type::BOOL {
        return get(row
            .try_get::<_, Option<bool>>(idx)
            .map(|v| v.map(Cell::Bool)));
    }
    if *ty == Type::INT2 {
        return get(row
            .try_get::<_, Option<i16>>(idx)
            .map(|v| v.map(|value| Cell::Int(i64::from(value)))));
    }
    if *ty == Type::INT4 {
        return get(row
            .try_get::<_, Option<i32>>(idx)
            .map(|v| v.map(|value| Cell::Int(i64::from(value)))));
    }
    if *ty == Type::INT8 {
        return get(row.try_get::<_, Option<i64>>(idx).map(|v| v.map(Cell::Int)));
    }
    if *ty == Type::FLOAT4 {
        return get(row
            .try_get::<_, Option<f32>>(idx)
            .map(|v| v.map(|value| Cell::Float(f64::from(value)))));
    }
    if *ty == Type::FLOAT8 {
        return get(row
            .try_get::<_, Option<f64>>(idx)
            .map(|v| v.map(Cell::Float)));
    }
    if *ty == Type::TEXT || *ty == Type::VARCHAR || *ty == Type::NAME || *ty == Type::BPCHAR {
        return get(row
            .try_get::<_, Option<String>>(idx)
            .map(|v| v.map(Cell::Text)));
    }
    if *ty == Type::TIMESTAMP || *ty == Type::TIMESTAMPTZ {
        return get(row
            .try_get::<_, Option<SystemTime>>(idx)
            .map(|time| time.and_then(system_time_micros).map(Cell::Time)));
    }
    Err(ConnectorFailure::Invalid)
}

/// One typed cell used for both identity encoding and resume parameters.
/// `Time` is microseconds since Unix epoch, matching PostgreSQL timestamp
/// precision so a resume parameter does not skip or repeat a row.
#[derive(Debug, Clone)]
enum Cell {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Time(i64),
}

impl Cell {
    fn as_text(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Int(value) => value.to_string(),
            Self::Float(value) => {
                if value.fract() == 0.0 && value.abs() < 1e15 {
                    format!("{value:.0}")
                } else {
                    value.to_string()
                }
            }
            Self::Text(value) => value.clone(),
            Self::Time(value) => value.to_string(),
        }
    }

    fn property(&self) -> PropertyValue {
        match self {
            Self::Bool(value) => PropertyValue::Bool(*value),
            Self::Int(value) => PropertyValue::Int(*value),
            // Cursor time is microseconds; timestamp properties are millis.
            Self::Time(value) => PropertyValue::Int(value.div_euclid(1_000)),
            Self::Float(value) => PropertyValue::Float(*value),
            Self::Text(value) => PropertyValue::String(value.clone()),
        }
    }

    fn encode(&self) -> String {
        match self {
            Self::Bool(true) => "b1".into(),
            Self::Bool(false) => "b0".into(),
            Self::Int(value) => format!("i{value}"),
            Self::Float(value) => format!("f{:x}", value.to_bits()),
            Self::Text(value) => format!("s{}", percent_encode(value)),
            Self::Time(value) => format!("t{value}"),
        }
    }

    fn decode(text: &str) -> Option<Self> {
        let (tag, rest) = text.split_at_checked(1)?;
        match tag {
            "b" => match rest {
                "1" => Some(Self::Bool(true)),
                "0" => Some(Self::Bool(false)),
                _ => None,
            },
            "i" => rest.parse().ok().map(Self::Int),
            "f" => u64::from_str_radix(rest, 16)
                .ok()
                .map(|bits| Self::Float(f64::from_bits(bits))),
            "s" => percent_decode(rest).map(Self::Text),
            "t" => rest.parse().ok().map(Self::Time),
            _ => None,
        }
    }
}

impl ToSql for Cell {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        match self {
            Self::Bool(value) => value.to_sql(ty, out),
            Self::Int(value) => {
                if i16::accepts(ty) {
                    i16::try_from(*value)?.to_sql(ty, out)
                } else if i32::accepts(ty) {
                    i32::try_from(*value)?.to_sql(ty, out)
                } else {
                    value.to_sql(ty, out)
                }
            }
            Self::Float(value) => {
                if f32::accepts(ty) && !f64::accepts(ty) {
                    (*value as f32).to_sql(ty, out)
                } else {
                    value.to_sql(ty, out)
                }
            }
            Self::Text(value) => value.to_sql(ty, out),
            Self::Time(us) => system_time_from_micros(*us)?.to_sql(ty, out),
        }
    }

    fn accepts(ty: &Type) -> bool {
        bool::accepts(ty)
            || i16::accepts(ty)
            || i32::accepts(ty)
            || i64::accepts(ty)
            || f32::accepts(ty)
            || f64::accepts(ty)
            || String::accepts(ty)
            || SystemTime::accepts(ty)
    }

    to_sql_checked!();
}

/// Where a scan stands: the last `(monotonic, key)` tuple, empty at the
/// start of a table, and whether a short page already completed the scan.
#[derive(Debug, Clone, Default, PartialEq)]
struct Cursor {
    after: Vec<Cell>,
    settled: bool,
}

impl Cursor {
    const PREFIX: &str = "rel-v1";

    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('|');
        if parts.next()? != Self::PREFIX {
            return None;
        }
        let (mono, pk, settled) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let settled = match settled {
            "settled" => true,
            "open" => false,
            _ => return None,
        };
        if mono.is_empty() && pk.is_empty() {
            return Some(Self {
                after: Vec::new(),
                settled,
            });
        }
        let mut after = vec![Cell::decode(mono)?];
        if !pk.is_empty() {
            after.extend(
                pk.split('~')
                    .map(Cell::decode)
                    .collect::<Option<Vec<_>>>()?,
            );
        }
        Some(Self { after, settled })
    }

    fn after(&self) -> Option<Vec<Cell>> {
        if self.after.is_empty() {
            None
        } else {
            Some(self.after.clone())
        }
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let settled = if self.settled { "settled" } else { "open" };
        match self.after.split_first() {
            None => write!(formatter, "{}|||{settled}", Self::PREFIX),
            Some((mono, pk)) => {
                let pk = pk.iter().map(Cell::encode).collect::<Vec<_>>().join("~");
                write!(
                    formatter,
                    "{}|{}|{pk}|{settled}",
                    Self::PREFIX,
                    mono.encode()
                )
            }
        }
    }
}

impl PartialEq for Cell {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Int(left), Self::Int(right)) | (Self::Time(left), Self::Time(right)) => {
                left == right
            }
            (Self::Float(left), Self::Float(right)) => left.to_bits() == right.to_bits(),
            (Self::Text(left), Self::Text(right)) => left == right,
            _ => false,
        }
    }
}

fn column_list(value: &str) -> Result<Vec<String>, ConnectorFailure> {
    let mut names = Vec::new();
    for part in value.split(',') {
        let name = column_name(part.trim())?;
        if names.contains(&name) {
            return Err(ConnectorFailure::Invalid);
        }
        names.push(name);
    }
    Ok(names)
}

fn column_name(name: &str) -> Result<String, ConnectorFailure> {
    quoted_ident(name)
        .map(|_| name.to_ascii_lowercase())
        .ok_or(ConnectorFailure::Invalid)
}

fn registered_token(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.contains('#')
        && !value.contains(':')
        && !value.contains('/')
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `table` or `schema.table` as a quoted identifier, when every part is a
/// plain identifier. Parts fold to lower case, as PostgreSQL folds an
/// unquoted name.
fn quoted_table(table: &str) -> Option<String> {
    let parts: Vec<&str> = table.split('.').collect();
    let plain = |part: &&str| {
        (1..=63).contains(&part.len())
            && part
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    };
    (parts.len() <= 2 && parts.iter().all(plain)).then(|| {
        parts
            .iter()
            .map(|part| format!("\"{}\"", part.to_ascii_lowercase()))
            .collect::<Vec<_>>()
            .join(".")
    })
}

fn quoted_ident(name: &str) -> Option<String> {
    quoted_table(name).filter(|quoted| !quoted.contains('.'))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// A database refusal as the connector's failure class.
fn failure(error: postgres::Error) -> ConnectorFailure {
    let Some(code) = error.code() else {
        // No server answer. The connection, TLS or the network failed, or
        // the client refused the table's shape (a column type, a missing
        // row), which is the Source's configuration.
        let source = std::error::Error::source(&error);
        let transport = error.is_closed()
            || source.is_some_and(|source| {
                source.is::<std::io::Error>() || source.is::<native_tls::Error>()
            });
        return if transport {
            ConnectorFailure::Unreachable
        } else {
            ConnectorFailure::Invalid
        };
    };
    match code.code().get(..2) {
        // Invalid authorization specification, invalid password.
        Some("28") => ConnectorFailure::AuthFailed,
        // Connection exception, insufficient resources, operator
        // intervention: the database is not there to serve.
        Some("08" | "53" | "57") => ConnectorFailure::Unreachable,
        _ if *code == SqlState::INSUFFICIENT_PRIVILEGE => ConnectorFailure::PermissionMissing,
        _ => ConnectorFailure::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Secret;
    use sekai_source_sdk::{PropertyValue, RELATIONAL_CONNECTOR, SourceConfig};
    use std::cmp::Ordering;
    use std::collections::BTreeMap;

    fn cmp_cells(left: &[Cell], right: &[Cell]) -> Ordering {
        for (left, right) in left.iter().zip(right) {
            let order = match (left, right) {
                (Cell::Bool(a), Cell::Bool(b)) => a.cmp(b),
                (Cell::Int(a), Cell::Int(b)) | (Cell::Time(a), Cell::Time(b)) => a.cmp(b),
                (Cell::Float(a), Cell::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
                (Cell::Text(a), Cell::Text(b)) => a.cmp(b),
                _ => Ordering::Equal,
            };
            if order != Ordering::Equal {
                return order;
            }
        }
        left.len().cmp(&right.len())
    }

    fn prepared(config: &[(&str, &str)], password: Option<&str>) -> Prepared {
        Prepared {
            connector: &RELATIONAL_CONNECTOR,
            source_instance: "sys/db/public/orders".into(),
            config: config
                .iter()
                .map(|(name, value)| (name.to_string(), ConfigValue::Text(value.to_string())))
                .collect::<SourceConfig>(),
            credentials: password
                .map(|password| BTreeMap::from([("password".into(), Secret(password.into()))]))
                .unwrap_or_default(),
        }
    }

    const BASE: [(&str, &str); 3] = [
        ("endpoint", "127.0.0.1:1"),
        ("database", "orders"),
        ("user", "writer"),
    ];

    const PAGE: [(&str, &str); 8] = [
        ("endpoint", "127.0.0.1:1"),
        ("database", "orders"),
        ("user", "writer"),
        ("table", "orders"),
        ("record_kind", "Order"),
        ("pk_columns", "id"),
        ("monotonic_column", "updated_at"),
        ("display_column", "name"),
    ];

    fn spec() -> ReadSpec {
        ReadSpec::parse(&prepared(&PAGE, Some("pw")).config).unwrap()
    }

    fn row(id: i64, updated_at: i64, name: &str) -> MemRow {
        MemRow {
            cells: BTreeMap::from([
                ("id".into(), Cell::Int(id)),
                ("updated_at".into(), Cell::Int(updated_at)),
                ("name".into(), Cell::Text(name.into())),
                ("password".into(), Cell::Text("hunter2".into())),
            ]),
        }
    }

    fn fetch(rows: &[MemRow], spec: &ReadSpec, cursor: Option<&str>, limit: usize) -> Vec<MemRow> {
        let after = cursor
            .and_then(Cursor::parse)
            .and_then(|cursor| cursor.after());
        let mut ordered: Vec<MemRow> = rows.to_vec();
        ordered.sort_by(|left, right| {
            cmp_cells(&left.order(spec).unwrap(), &right.order(spec).unwrap())
        });
        ordered
            .into_iter()
            .filter(|row| {
                after.as_ref().is_none_or(|after| {
                    cmp_cells(&row.order(spec).unwrap(), after) == Ordering::Greater
                })
            })
            .take(limit)
            .collect()
    }

    fn read(spec: &ReadSpec, rows: &[MemRow], cursor: Option<&str>, limit: usize) -> SnapshotRead {
        let fetched = fetch(rows, spec, cursor, limit);
        page_of(
            spec,
            "postgres.table",
            "sys/db/public/orders",
            &fetched,
            cursor,
            limit,
            1,
        )
        .unwrap()
    }

    fn page(read: SnapshotRead) -> SnapshotPage {
        match read {
            SnapshotRead::Page(page) => page,
            SnapshotRead::Complete => panic!("a page"),
        }
    }

    /// Reads pages as the runtime does, committing each cursor, until the
    /// scan is complete; returns the keys read per page.
    fn scan(spec: &ReadSpec, rows: &[MemRow], cursor: &mut Option<String>) -> Vec<Vec<String>> {
        let mut pages = Vec::new();
        while let SnapshotRead::Page(page) = read(spec, rows, cursor.as_deref(), 2) {
            assert_ne!(Some(&page.proposed_next_cursor), cursor.as_ref());
            pages.push(
                page.records
                    .iter()
                    .map(|record| record.external_id.clone())
                    .collect(),
            );
            *cursor = Some(page.proposed_next_cursor);
            assert!(pages.len() < 10, "the scan ends");
        }
        pages
    }

    #[test]
    fn delivery_tables_are_plain_identifiers() {
        assert_eq!(quoted_table("exports").as_deref(), Some("\"exports\""));
        assert_eq!(
            quoted_table("Ops.Exports_v2").as_deref(),
            Some("\"ops\".\"exports_v2\"")
        );
        for refused in [
            "",
            "a.b.c",
            "1exports",
            "exports; DROP TABLE x",
            "ex\"ports",
            ".exports",
        ] {
            assert_eq!(quoted_table(refused), None, "{refused}");
        }
    }

    #[test]
    fn a_source_opens_only_with_its_settings() {
        let tls = tls(None).unwrap();
        let open =
            |config: &[(&str, &str)], password| open(&prepared(config, password), &tls).map(|_| ());
        assert_eq!(open(&BASE, Some("pw")), Ok(()));
        assert_eq!(open(&BASE, None), Err(ConnectorFailure::AuthFailed));
        assert_eq!(
            open(&BASE[1..], Some("pw")),
            Err(ConnectorFailure::Invalid),
            "no endpoint"
        );
        let mut bad_table = BASE.to_vec();
        bad_table.push(("delivery_table", "x; --"));
        assert_eq!(open(&bad_table, Some("pw")), Err(ConnectorFailure::Invalid));
        assert!(super::tls(Some(b"not a certificate")).is_err());
    }

    /// On a blocking thread of the runtime, as deliveries run: the
    /// client's own executor starts there without a nested-runtime panic.
    #[tokio::test]
    async fn an_unreachable_database_fails_as_unreachable() {
        let check = crate::sync::blocking(|| {
            // Port 1 on loopback refuses the connection.
            let mut relational = open(&prepared(&BASE, Some("pw")), &tls(None).unwrap()).unwrap();
            Ok(relational.check())
        });
        assert_eq!(check.await, Ok(Err(ConnectorFailure::Unreachable)));
    }

    #[test]
    fn delivering_without_a_delivery_table_is_invalid() {
        let mut relational = open(&prepared(&BASE, Some("pw")), &tls(None).unwrap()).unwrap();
        let artifact = ExportArtifact {
            receipt_id: "r1",
            namespace: "ops",
            definition_id: "d1",
            content_digest: "sha256:00",
            bytes: b"x",
        };
        assert_eq!(
            relational.deliver(&artifact),
            Err(ConnectorFailure::Invalid)
        );
    }

    #[test]
    fn a_scan_pages_by_key_then_reads_only_what_changed() {
        let spec = spec();
        let mut rows = vec![
            row(1, 10, "a"),
            row(2, 20, "b"),
            row(3, 30, "c"),
            row(4, 40, "d"),
            row(5, 50, "e"),
        ];
        let mut cursor = None;
        let first = page(read(&spec, &rows, None, 2));
        assert_eq!(
            first.records[0].source_id(),
            "postgres.table:sys/db/public/orders#1"
        );
        assert_eq!(first.records[0].type_name, "Order");
        assert!(
            first
                .records
                .iter()
                .all(|record| !record.properties.contains_key("password"))
        );
        assert_eq!(
            scan(&spec, &rows, &mut cursor),
            [vec!["1", "2"], vec!["3", "4"], vec!["5"]]
        );
        assert!(
            scan(&spec, &rows, &mut cursor).is_empty(),
            "nothing changed"
        );

        rows[0] = row(1, 60, "a");
        rows.push(row(6, 70, "f"));
        let changed: Vec<String> = scan(&spec, &rows, &mut cursor).concat();
        assert!(changed.contains(&"1".to_string()), "{changed:?}");
        assert!(changed.contains(&"6".to_string()), "{changed:?}");
        assert!(!changed.contains(&"2".to_string()), "{changed:?}");
    }

    #[test]
    fn a_kill_mid_snapshot_resumes_every_row_once() {
        let spec = spec();
        let rows: Vec<_> = (1..=5).map(|id| row(id, id * 10, "n")).collect();
        let first = page(read(&spec, &rows, None, 2));
        assert_eq!(
            first
                .records
                .iter()
                .map(|record| record.external_id.as_str())
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
        assert!(!first.complete);
        let mut cursor = Some(first.proposed_next_cursor);
        let rest: Vec<String> = scan(&spec, &rows, &mut cursor).concat();
        let mut all = first
            .records
            .iter()
            .map(|record| record.external_id.clone())
            .chain(rest)
            .collect::<Vec<_>>();
        all.sort();
        all.dedup();
        assert_eq!(all, ["1", "2", "3", "4", "5"]);
    }

    #[test]
    fn composite_keys_encode_and_resume() {
        let mut config = PAGE.to_vec();
        config[5] = ("pk_columns", "tenant,id");
        let spec = ReadSpec::parse(&prepared(&config, Some("pw")).config).unwrap();
        let row = |tenant: &str, id: i64, updated_at: i64| MemRow {
            cells: BTreeMap::from([
                ("tenant".into(), Cell::Text(tenant.into())),
                ("id".into(), Cell::Int(id)),
                ("updated_at".into(), Cell::Int(updated_at)),
                ("name".into(), Cell::Text("n".into())),
            ]),
        };
        let rows = [row("acme", 1, 10), row("acme", 2, 20), row("beta/x", 1, 30)];
        let first = page(read(&spec, &rows, None, 2));
        assert_eq!(first.records[0].external_id, "acme~1");
        assert_eq!(first.records[1].external_id, "acme~2");
        assert!(!first.complete);
        let second = page(read(&spec, &rows, Some(&first.proposed_next_cursor), 2));
        assert_eq!(second.records[0].external_id, "beta%2Fx~1");
        assert!(second.complete);
    }

    #[test]
    fn a_cursor_another_adapter_wrote_restarts_the_scan() {
        let spec = spec();
        let rows = [row(1, 10, "a")];
        let read = page(read(&spec, &rows, Some("legacy-7"), 10));
        assert!(read.complete);
        assert_eq!(read.records[0].external_id, "1");
        assert_ne!(read.proposed_next_cursor, "legacy-7");
    }

    #[test]
    fn null_keys_and_missing_page_config_fail_closed() {
        let spec = spec();
        let mut missing = row(1, 10, "a");
        missing.cells.remove("id");
        assert_eq!(
            page_of(
                &spec,
                "postgres.table",
                "sys/db/public/orders",
                &[missing],
                None,
                10,
                1
            ),
            Err(ConnectorFailure::Invalid)
        );
        assert!(ReadSpec::parse(&prepared(&BASE, Some("pw")).config).is_err());
        let sql = spec.select_sql(true, 2);
        assert!(sql.contains("WHERE (\"updated_at\", \"id\") > ($1, $2)"));
        assert!(sql.contains("ORDER BY \"updated_at\", \"id\" LIMIT 2"));
        assert_eq!(quoted_ident("id").as_deref(), Some("\"id\""));
        assert_eq!(quoted_ident("public.orders"), None);
    }

    #[test]
    fn restricted_page_fields_fail_closed() {
        let mut email = PAGE.to_vec();
        email.push(("display_column", "email"));
        assert!(ReadSpec::parse(&prepared(&email, Some("pw")).config).is_err());
        let mut password_key = PAGE.to_vec();
        password_key[5] = ("pk_columns", "password");
        assert!(ReadSpec::parse(&prepared(&password_key, Some("pw")).config).is_err());
        let first = page(read(&spec(), &[row(1, 10, "a")], None, 10));
        assert_eq!(first.records[0].display_name, "a");
        assert!(!first.records[0].properties.contains_key("password"));
    }

    #[test]
    fn primary_key_must_match_the_relation() {
        assert!(primary_key_matches(&["id".into()], &["id".into()]));
        assert!(!primary_key_matches(&["id".into()], &[]));
        assert!(!primary_key_matches(
            &["id".into()],
            &["id".into(), "tenant".into()]
        ));
        assert!(!primary_key_matches(
            &["tenant".into(), "id".into()],
            &["id".into(), "tenant".into()]
        ));
        assert_eq!(relation_name("\"orders\""), "orders");
        assert_eq!(relation_name("\"public\".\"orders\""), "public.orders");
        let mut cells = BTreeMap::new();
        insert_cell(&mut cells, "id".into(), Cell::Int(1)).unwrap();
        assert_eq!(
            insert_cell(&mut cells, "id".into(), Cell::Int(2)),
            Err(ConnectorFailure::Invalid)
        );
        assert_eq!(Cell::Time(1_234_567).property(), PropertyValue::Int(1_234));
        assert_eq!(
            Cell::Time(-1_500_000).property(),
            PropertyValue::Int(-1_500)
        );
        let mut wide = PAGE.to_vec();
        wide[5] = ("pk_columns", "a,b,c,d,e,f,g,h");
        assert!(ReadSpec::parse(&prepared(&wide, Some("pw")).config).is_err());
    }

    #[test]
    fn cursors_round_trip_typed_cells() {
        let cursor = Cursor {
            after: vec![
                Cell::Time(-1_234_567),
                Cell::Int(40),
                Cell::Text("a/b".into()),
            ],
            settled: false,
        };
        let text = cursor.to_string();
        assert!(text.starts_with("rel-v1|t-1234567|"));
        assert_eq!(Cursor::parse(&text), Some(cursor));
        assert_eq!(Cursor::parse("github-v1|||open"), None);
        assert_eq!(percent_encode("a/b~c"), "a%2Fb%7Ec");
        assert_eq!(percent_decode("a%2Fb%7Ec").as_deref(), Some("a/b~c"));
    }

    /// Pages a real PostgreSQL table over TLS. Run through
    /// `scripts/postgres-conformance.sh`, which sets
    /// `SEKAI_TEST_POSTGRES_URL` and `SEKAI_TEST_POSTGRES_CA_CERT`.
    #[test]
    #[ignore = "requires PostgreSQL; run scripts/postgres-conformance.sh"]
    fn postgres_page_reads_resume_and_increment() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL").expect("SEKAI_TEST_POSTGRES_URL");
        let ca = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT")
            .map(|path| std::fs::read(path).expect("read CA certificate"))
            .ok();
        let tls = tls(ca.as_deref()).unwrap();
        let target: postgres::Config = url.parse().unwrap();
        let host = match &target.get_hosts()[0] {
            postgres::config::Host::Tcp(host) => host.clone(),
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => panic!("a TCP URL"),
        };
        let password = String::from_utf8(target.get_password().unwrap().to_vec()).unwrap();
        let table = format!(
            "page_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut admin = target.connect(tls.clone()).unwrap();
        admin
            .batch_execute(&format!(
                "CREATE TABLE {table} (id int PRIMARY KEY, name text NOT NULL, \
                 updated_at bigint NOT NULL, password text NOT NULL)"
            ))
            .unwrap();
        admin
            .batch_execute(&format!(
                "INSERT INTO {table} (id, name, updated_at, password) VALUES \
                 (1, 'a', 10, 'secret'), (2, 'b', 20, 'secret'), (3, 'c', 30, 'secret'), \
                 (4, 'd', 40, 'secret'), (5, 'e', 50, 'secret')"
            ))
            .unwrap();
        let host = if host == "localhost" {
            "127.0.0.1".to_string()
        } else {
            host
        };
        let endpoint = format!("{host}:{}", target.get_ports()[0]);
        let config = [
            ("endpoint", endpoint.as_str()),
            ("database", target.get_dbname().unwrap()),
            ("user", target.get_user().unwrap()),
            ("table", table.as_str()),
            ("record_kind", "Order"),
            ("pk_columns", "id"),
            ("monotonic_column", "updated_at"),
            ("display_column", "name"),
        ];
        let mut relational = open(&prepared(&config, Some(&password)), &tls).unwrap();
        let first = page(relational.read_page(None, 2).unwrap());
        assert_eq!(
            first
                .records
                .iter()
                .map(|record| record.external_id.as_str())
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
        assert!(
            first
                .records
                .iter()
                .all(|record| !record.properties.contains_key("password"))
        );
        let mut cursor = Some(first.proposed_next_cursor);
        let mut ids = first
            .records
            .iter()
            .map(|record| record.external_id.clone())
            .collect::<Vec<_>>();
        while let SnapshotRead::Page(page) = relational.read_page(cursor.as_deref(), 2).unwrap() {
            ids.extend(page.records.iter().map(|record| record.external_id.clone()));
            cursor = Some(page.proposed_next_cursor);
            if page.complete {
                break;
            }
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids, ["1", "2", "3", "4", "5"]);
        assert!(matches!(
            relational.read_page(cursor.as_deref(), 2).unwrap(),
            SnapshotRead::Complete
        ));
        admin
            .batch_execute(&format!(
                "UPDATE {table} SET updated_at = 60, name = 'A' WHERE id = 1; \
                 INSERT INTO {table} (id, name, updated_at, password) VALUES (6, 'f', 70, 'secret')"
            ))
            .unwrap();
        let mut changed = Vec::new();
        while let SnapshotRead::Page(page) = relational.read_page(cursor.as_deref(), 2).unwrap() {
            changed.extend(page.records.iter().map(|record| record.external_id.clone()));
            cursor = Some(page.proposed_next_cursor);
            if page.complete {
                break;
            }
        }
        assert!(changed.contains(&"1".to_string()), "{changed:?}");
        assert!(changed.contains(&"6".to_string()), "{changed:?}");
        admin.batch_execute(&format!("DROP TABLE {table}")).unwrap();
    }

    /// Delivers into a real PostgreSQL over TLS. Run through
    /// `scripts/postgres-conformance.sh`, which sets
    /// `SEKAI_TEST_POSTGRES_URL` and `SEKAI_TEST_POSTGRES_CA_CERT`.
    #[test]
    #[ignore = "requires PostgreSQL; run scripts/postgres-conformance.sh"]
    fn postgres_delivery_is_idempotent_per_receipt() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL").expect("SEKAI_TEST_POSTGRES_URL");
        let ca = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT")
            .map(|path| std::fs::read(path).expect("read CA certificate"))
            .ok();
        let tls = tls(ca.as_deref()).unwrap();
        let target: postgres::Config = url.parse().unwrap();
        let host = match &target.get_hosts()[0] {
            postgres::config::Host::Tcp(host) => host.clone(),
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => panic!("a TCP URL"),
        };
        let password = String::from_utf8(target.get_password().unwrap().to_vec()).unwrap();
        // A table of its own, so another run against the same database
        // never meets this one's rows.
        let table = format!(
            "delivery_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut admin = target.connect(tls.clone()).unwrap();
        admin
            .batch_execute(&format!(
                "CREATE TABLE {table} (receipt_id text PRIMARY KEY, namespace text NOT NULL, \
                 definition_id text NOT NULL, content_digest text NOT NULL, content bytea NOT NULL)"
            ))
            .unwrap();
        // One address: the client reports the last address's failure, so
        // a name that also resolves to an address nothing listens on would
        // hide an authentication failure behind a refused connection.
        let host = if host == "localhost" {
            "127.0.0.1".to_string()
        } else {
            host
        };
        let endpoint = format!("{host}:{}", target.get_ports()[0]);
        let config = [
            ("endpoint", endpoint.as_str()),
            ("database", target.get_dbname().unwrap()),
            ("user", target.get_user().unwrap()),
            ("delivery_table", table.as_str()),
        ];
        let mut relational = open(&prepared(&config, Some(&password)), &tls).unwrap();
        relational.check().unwrap();
        let artifact = ExportArtifact {
            receipt_id: "r1",
            namespace: "ops",
            definition_id: "d1",
            content_digest: "sha256:aa",
            bytes: b"rows",
        };
        relational.deliver(&artifact).unwrap();
        relational.deliver(&artifact).unwrap();
        let conflicting = ExportArtifact {
            content_digest: "sha256:bb",
            ..artifact
        };
        assert_eq!(
            relational.deliver(&conflicting),
            Err(ConnectorFailure::Invalid)
        );
        let rows = admin
            .query(&format!("SELECT content_digest, content FROM {table}"), &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, String>(0), "sha256:aa");
        assert_eq!(rows[0].get::<_, Vec<u8>>(1), b"rows");
        let mut wrong = open(&prepared(&config, Some("wrong")), &tls).unwrap();
        assert_eq!(wrong.check(), Err(ConnectorFailure::AuthFailed));
        // A table of another shape is the Source's configuration, refused
        // by the client before the server answers.
        let misshaped = format!("{table}_uuid");
        admin
            .batch_execute(&format!(
                "CREATE TABLE {misshaped} (receipt_id uuid PRIMARY KEY, namespace text, \
                 definition_id text, content_digest text, content bytea)"
            ))
            .unwrap();
        let mut config = config;
        config[3].1 = misshaped.as_str();
        let mut relational = open(&prepared(&config, Some(&password)), &tls).unwrap();
        assert_eq!(
            relational.deliver(&artifact),
            Err(ConnectorFailure::Invalid)
        );
        admin
            .batch_execute(&format!("DROP TABLE {table}; DROP TABLE {misshaped}"))
            .unwrap();
    }
}
