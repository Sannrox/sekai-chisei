//! Watermarked export fingerprints (#1466, ADR 0131).
//!
//! A marking's `fingerprint_properties` allowlist, empty by default, is the
//! only thing that turns fingerprinting on. Listed decimal measurements move
//! by at most one unit in the last decimal place, keyed by the export id.
//! Exact-value properties stay as the reader saw them. A fingerprinted
//! export also permutes row groups and stores a compact record so
//! `TraceExport` can score a leaked fragment.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;
use crate::sekai::data_export::{EXPORT_CONTRACT, ExportFormat, RowEncoder, export_receipt};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;

pub const FINGERPRINT_GROUP_SIZE: usize = 16;
const MIN_TRACE_CELLS: u64 = 8;
const TRACE_SCORE_FLOOR: f64 = 0.75;
const TRACE_FAMILY_P: f64 = 0.01;
const MAX_MARKING: usize = 128;
const MAX_SAMPLE_BYTES: usize = 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// Policy that enables fingerprinting for one marking in one namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportFingerprintPolicy {
    pub namespace: String,
    pub marking: String,
    pub fingerprint_properties: Vec<String>,
    pub updated_by: String,
    pub updated_at_ms: i64,
}

/// Compact record of one fingerprinted export, keyed by its receipt id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportFingerprintRecord {
    pub operation_id: String,
    pub namespace: String,
    pub columns: Vec<String>,
    pub group_size: u32,
    /// True when the export led with an object id; false for dataset rows,
    /// including a dataset column that happens to be named `id`.
    #[serde(default)]
    pub id_column: bool,
}

/// One scored candidate from a leaked sample.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceMatch {
    pub receipt_id: String,
    pub score: f64,
    pub cells: u64,
    pub matches: u64,
}

/// Allowlists that apply during one export, keyed by marking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintPlan {
    by_marking: BTreeMap<String, Vec<String>>,
}

impl FingerprintPlan {
    /// Sorted union of every listed property.
    pub fn properties(&self) -> Vec<String> {
        let mut names = self
            .by_marking
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        names
    }

    fn for_marking(&self, marking: &str) -> &[String] {
        self.by_marking
            .get(marking)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Policies with a non-empty allowlist on `namespace`, if any.
pub fn namespace_plan(db: &RuntimeDb, namespace: &str) -> Result<Option<FingerprintPlan>, String> {
    let mut by_marking = BTreeMap::new();
    for policy in db.list_export_fingerprint_policies(namespace)? {
        if !policy.fingerprint_properties.is_empty() {
            by_marking.insert(policy.marking, policy.fingerprint_properties);
        }
    }
    Ok((!by_marking.is_empty()).then_some(FingerprintPlan { by_marking }))
}

/// Stores the policy; an empty allowlist turns fingerprinting off for that
/// marking. Namespace administration is checked by the caller.
pub fn put_fingerprint_policy(
    db: &RuntimeDb,
    namespace: &str,
    marking: &str,
    properties: Vec<String>,
    actor: &str,
    now_ms: i64,
) -> Result<ExportFingerprintPolicy, String> {
    let namespace = check_namespace(namespace)?;
    let marking = check_marking(marking)?;
    let fingerprint_properties = check_properties(properties)?;
    let previous = db.get_export_fingerprint_policy(namespace, marking)?;
    let policy = ExportFingerprintPolicy {
        namespace: namespace.into(),
        marking: marking.into(),
        fingerprint_properties,
        updated_by: actor.into(),
        updated_at_ms: now_ms,
    };
    db.put_export_fingerprint_policy(&policy)?;
    db.record_decision(&Decision {
        id: format!(
            "export-fingerprint-policy:{}",
            uuid::Uuid::new_v4().simple()
        ),
        timestamp: now_ms,
        actor: actor.into(),
        action: "export_fingerprint_policy".into(),
        reason: format!("export fingerprint policy under {EXPORT_CONTRACT}"),
        evidence: HashMap::from([
            ("contract_version".into(), EXPORT_CONTRACT.into()),
            ("namespace".into(), namespace.into()),
            ("marking".into(), marking.into()),
            (
                "fingerprint_properties".into(),
                policy.fingerprint_properties.join(","),
            ),
            (
                "previous_properties".into(),
                previous
                    .map(|prior| prior.fingerprint_properties.join(","))
                    .unwrap_or_default(),
            ),
        ]),
        target_id: format!("{namespace}:{marking}"),
        outcome: if policy.fingerprint_properties.is_empty() {
            "off".into()
        } else {
            "on".into()
        },
    })?;
    Ok(policy)
}

/// The stored policy, or an empty allowlist when none has been put.
pub fn get_fingerprint_policy(
    db: &RuntimeDb,
    namespace: &str,
    marking: &str,
) -> Result<ExportFingerprintPolicy, String> {
    let namespace = check_namespace(namespace)?;
    let marking = check_marking(marking)?;
    Ok(db
        .get_export_fingerprint_policy(namespace, marking)?
        .unwrap_or(ExportFingerprintPolicy {
            namespace: namespace.into(),
            marking: marking.into(),
            fingerprint_properties: Vec::new(),
            updated_by: String::new(),
            updated_at_ms: 0,
        }))
}

/// Persists the compact fingerprint record of one export.
pub fn record_export_fingerprint(
    db: &RuntimeDb,
    record: &ExportFingerprintRecord,
) -> Result<(), String> {
    db.put_export_fingerprint(record)
}

/// Scores `sample` against fingerprint records in `namespace`. `admin` sees
/// every match; anyone else sees only exports they initiated. Refusing and
/// completing are both audited.
pub fn trace_export(
    db: &RuntimeDb,
    namespace: &str,
    format: ExportFormat,
    sample: &[u8],
    actor: &str,
    now_ms: i64,
    admin: bool,
) -> Result<Vec<TraceMatch>, String> {
    let namespace = check_namespace(namespace)?;
    let digest = format!("sha256:{:x}", Sha256::digest(sample));
    let audit = |outcome: &str, matches: &[TraceMatch]| {
        db.record_decision(&Decision {
            id: format!("trace-export:{}", uuid::Uuid::new_v4().simple()),
            timestamp: now_ms,
            actor: actor.into(),
            action: "trace_export".into(),
            reason: format!("export fingerprint trace under {EXPORT_CONTRACT}"),
            evidence: HashMap::from([
                ("contract_version".into(), EXPORT_CONTRACT.into()),
                ("namespace".into(), namespace.into()),
                ("format".into(), format_name(format).into()),
                ("sample_sha256".into(), digest.clone()),
                (
                    "matches".into(),
                    matches
                        .iter()
                        .map(|found| found.receipt_id.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ]),
            target_id: namespace.into(),
            outcome: outcome.into(),
        })
    };
    if sample.is_empty() || sample.len() > MAX_SAMPLE_BYTES {
        audit("invalid", &[])?;
        return Err(format!("sample must be 1 to {MAX_SAMPLE_BYTES} bytes"));
    }
    let records = db.list_export_fingerprints(namespace)?;
    if !admin {
        let visible = records.iter().any(|record| {
            export_receipt(db, &record.operation_id)
                .ok()
                .flatten()
                .is_some_and(|receipt| receipt.initiating_actor == actor)
        });
        if !visible {
            audit("denied", &[])?;
            return Err(crate::sekai::data_export::EXPORT_DENIED.into());
        }
    }
    let parsed = match parse_sample(format, sample) {
        Ok(rows) => rows,
        Err(error) => {
            audit("invalid", &[])?;
            return Err(error);
        }
    };
    let mut considered = Vec::new();
    for record in &records {
        if !admin {
            let Some(receipt) = export_receipt(db, &record.operation_id)? else {
                continue;
            };
            if receipt.initiating_actor != actor {
                continue;
            }
        }
        considered.push(record);
    }
    let candidates = considered.len() as u64;
    let mut matches = Vec::new();
    for record in considered {
        if let Some(found) = score_sample(record, &parsed, candidates) {
            matches.push(found);
        }
    }
    matches.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    audit("completed", &matches)?;
    Ok(matches)
}

/// Buffers rows, fingerprints listed decimals, and permutes groups of
/// [`FINGERPRINT_GROUP_SIZE`]. With no plan, each row is encoded as-is.
pub struct FingerprintSink {
    export_id: String,
    encoder: RowEncoder,
    plan: Option<FingerprintPlan>,
    group: Vec<(String, HashMap<String, String>)>,
    group_index: u64,
}

impl FingerprintSink {
    pub fn new(export_id: String, encoder: RowEncoder, plan: Option<FingerprintPlan>) -> Self {
        Self {
            export_id,
            encoder,
            plan,
            group: Vec::with_capacity(FINGERPRINT_GROUP_SIZE),
            group_index: 0,
        }
    }

    /// Fingerprints `values` under `marking` and returns encoded rows once a
    /// group fills. `marking` is the row's `access_marking`; unmarked rows
    /// are encoded as-is. Extra keys that the encoder will not emit are
    /// dropped so a dataset row without an id keys HMAC from the file.
    pub fn push(
        &mut self,
        id: &str,
        marking: &str,
        mut values: HashMap<String, String>,
    ) -> Result<Vec<crate::sekai::data_export::EncodedPart>, String> {
        values.retain(|name, _| self.encoder.columns().iter().any(|column| column == name));
        if let Some(plan) = &self.plan {
            apply_row(
                &self.export_id,
                plan,
                id,
                marking,
                &mut values,
                self.encoder.id_column(),
            )?;
            self.group.push((id.to_string(), values));
            if self.group.len() == FINGERPRINT_GROUP_SIZE {
                return Ok(self.flush_group());
            }
            return Ok(Vec::new());
        }
        Ok(self.encoder.push(id, &values).into_iter().collect())
    }

    /// Encodes any buffered remainder, then the format's trailer.
    pub fn finish(&mut self) -> Vec<crate::sekai::data_export::EncodedPart> {
        let mut out = if self.plan.is_none() || self.group.is_empty() {
            Vec::new()
        } else {
            self.flush_group()
        };
        if let Some(part) = self.encoder.finish() {
            out.push(part);
        }
        out
    }

    fn flush_group(&mut self) -> Vec<crate::sekai::data_export::EncodedPart> {
        permute_group(&self.export_id, self.group_index, &mut self.group);
        self.group_index += 1;
        let rows = std::mem::take(&mut self.group);
        rows.into_iter()
            .filter_map(|(id, values)| self.encoder.push(&id, &values))
            .collect()
    }
}

fn apply_row(
    export_id: &str,
    plan: &FingerprintPlan,
    id: &str,
    marking: &str,
    values: &mut HashMap<String, String>,
    id_column: bool,
) -> Result<(), String> {
    let listed = plan.for_marking(marking.trim());
    if listed.is_empty() {
        return Ok(());
    }
    let key = row_key(id, values, &plan.properties(), id_column);
    for property in listed {
        let Some(value) = values.get(property) else {
            continue;
        };
        match classify_cell(value) {
            CellKind::Absent => {}
            CellKind::Measurement => {
                let bit = hmac_bit(export_id, &key, property);
                let watermarked = set_last_digit_parity(value, bit);
                values.insert(property.clone(), watermarked);
            }
            CellKind::Forbidden(kind) => {
                return Err(format!(
                    "fingerprint property {property} is {kind}, not a decimal measurement"
                ));
            }
        }
    }
    Ok(())
}

fn row_key(
    id: &str,
    values: &HashMap<String, String>,
    listed: &[String],
    id_column: bool,
) -> String {
    if id_column && !id.is_empty() {
        return id.to_string();
    }
    let mut parts = values
        .iter()
        .filter(|(name, value)| !value.is_empty() && !listed.iter().any(|listed| listed == *name))
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    if parts.is_empty() {
        // A dataset of only listed measurements has no exact column left.
        // Drop the last digit, which is the watermark, so encode and trace
        // reconstruct the same stem.
        parts = values
            .iter()
            .filter(|(name, value)| {
                listed.iter().any(|listed| listed == *name) && !value.is_empty()
            })
            .map(|(name, value)| format!("{name}={}", measurement_stem(value)))
            .collect();
    }
    parts.sort();
    parts.join("\n")
}

fn measurement_stem(value: &str) -> String {
    let value = value.trim();
    match value.char_indices().last() {
        Some((index, ch)) if ch.is_ascii_digit() => value[..index].to_string(),
        _ => value.to_string(),
    }
}

const HMAC_KEY: &[u8] = b"sekai.export-fingerprint/v1";

fn hmac_bit(export_id: &str, row_id: &str, property: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(HMAC_KEY).unwrap_or_else(|_| unreachable!());
    for part in [export_id, row_id, property] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    mac.finalize().into_bytes()[0] & 1 == 1
}

fn permute_group<T>(export_id: &str, group_index: u64, items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = keyed_index(export_id, group_index, i as u64) as usize % (i + 1);
        items.swap(i, j);
    }
}

fn keyed_index(export_id: &str, group_index: u64, i: u64) -> u64 {
    let mut mac = HmacSha256::new_from_slice(HMAC_KEY).unwrap_or_else(|_| unreachable!());
    mac.update(&(export_id.len() as u64).to_be_bytes());
    mac.update(export_id.as_bytes());
    mac.update(b"permute");
    mac.update(&group_index.to_be_bytes());
    mac.update(&i.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellKind {
    Absent,
    Measurement,
    Forbidden(&'static str),
}

/// Kind of a cell as it is exported. Put cannot see the object schema, and
/// there is no decimal property type, so a listed name present as integer,
/// boolean, timestamp, or other non-decimal spelling refuses the export.
fn classify_cell(value: &str) -> CellKind {
    let value = value.trim();
    if value.is_empty() || value == "[redacted]" {
        return CellKind::Absent;
    }
    if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
        return CellKind::Forbidden("boolean");
    }
    if looks_like_timestamp(value) {
        return CellKind::Forbidden("timestamp");
    }
    if is_integer(value) {
        return CellKind::Forbidden("integer");
    }
    if is_decimal_measurement(value) {
        return CellKind::Measurement;
    }
    CellKind::Forbidden("string")
}

fn is_integer(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_decimal_measurement(value: &str) -> bool {
    let value = value.trim();
    let Some((whole, frac)) = value.split_once('.') else {
        return false;
    };
    let whole = whole.strip_prefix('-').unwrap_or(whole);
    !whole.is_empty()
        && !frac.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && frac.bytes().all(|b| b.is_ascii_digit())
}

fn looks_like_timestamp(value: &str) -> bool {
    value.contains('T') && value.contains('-') && value.len() >= 10
}

fn set_last_digit_parity(value: &str, odd: bool) -> String {
    let value = value.trim();
    let mut chars: Vec<char> = value.chars().collect();
    let Some(last) = chars.last_mut() else {
        return value.to_string();
    };
    let Some(digit) = last.to_digit(10) else {
        return value.to_string();
    };
    let want_odd = u32::from(odd);
    if digit % 2 == want_odd {
        return value.to_string();
    }
    let next = if digit == 0 { 1 } else { digit - 1 };
    *last = char::from_digit(next, 10).expect("digit 0-9");
    chars.into_iter().collect()
}

fn last_digit_odd(value: &str) -> Option<bool> {
    value
        .trim()
        .chars()
        .last()?
        .to_digit(10)
        .map(|digit| digit % 2 == 1)
}

struct SampleRow {
    id: String,
    values: HashMap<String, String>,
}

fn parse_sample(format: ExportFormat, sample: &[u8]) -> Result<Vec<SampleRow>, String> {
    match format {
        ExportFormat::Csv => {
            let text =
                std::str::from_utf8(sample).map_err(|_| "sample is not utf-8".to_string())?;
            parse_csv(text)
        }
        ExportFormat::JsonLines => {
            let text =
                std::str::from_utf8(sample).map_err(|_| "sample is not utf-8".to_string())?;
            parse_jsonl(text)
        }
        ExportFormat::Parquet => parse_parquet(sample),
    }
}

fn parse_parquet(sample: &[u8]) -> Result<Vec<SampleRow>, String> {
    let table = sekai_parquet_export::decode(sample).map_err(|error| error.to_string())?;
    Ok(table
        .rows
        .into_iter()
        .map(|row| {
            let mut values = row.values;
            if table.id_column && !row.id.is_empty() {
                values.insert("id".into(), row.id.clone());
            }
            SampleRow { id: row.id, values }
        })
        .collect())
}

fn parse_csv(text: &str) -> Result<Vec<SampleRow>, String> {
    let mut records = csv_records(text)
        .into_iter()
        .filter(|fields| fields.iter().any(|field| !field.is_empty()));
    let header = records.next().ok_or("sample has no csv header")?;
    let id_at = header.iter().position(|name| name == "id");
    let mut rows = Vec::new();
    for fields in records {
        let mut values = HashMap::new();
        let mut id = String::new();
        for (index, name) in header.iter().enumerate() {
            let field = fields.get(index).cloned().unwrap_or_default();
            if Some(index) == id_at {
                id = field.clone();
            }
            values.insert(name.clone(), field);
        }
        rows.push(SampleRow { id, values });
    }
    Ok(rows)
}

/// Splits CSV into records, keeping quoted newlines inside a field.
fn csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    quoted = false;
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == ',' {
            fields.push(std::mem::take(&mut current));
        } else if ch == '\n' {
            fields.push(std::mem::take(&mut current));
            records.push(std::mem::take(&mut fields));
        } else if ch != '\r' {
            current.push(ch);
        }
    }
    if !current.is_empty() || !fields.is_empty() {
        fields.push(current);
        records.push(fields);
    }
    records
}

fn parse_jsonl(text: &str) -> Result<Vec<SampleRow>, String> {
    let mut rows = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|error| error.to_string())?;
        let object = value
            .as_object()
            .ok_or_else(|| "jsonl row must be an object".to_string())?;
        let mut values = HashMap::new();
        let mut id = String::new();
        for (key, value) in object {
            let text = match value {
                serde_json::Value::String(text) => text.clone(),
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::Bool(flag) => flag.to_string(),
                serde_json::Value::Null => String::new(),
                _ => continue,
            };
            if key == "id" {
                id = text.clone();
            }
            values.insert(key.clone(), text);
        }
        rows.push(SampleRow { id, values });
    }
    Ok(rows)
}

/// Scores each listed property on its own so a second marking's column does
/// not drown the one this export actually moved. Unmarked decimals in that
/// same column still count: the compact record has no per-row applicability
/// bit, and the 0.75 floor plus a binomial tail against chance is the bar.
fn score_sample(
    record: &ExportFingerprintRecord,
    rows: &[SampleRow],
    candidates: u64,
) -> Option<TraceMatch> {
    let mut best: Option<TraceMatch> = None;
    for property in &record.columns {
        let mut seen = BTreeSet::new();
        let mut cells = 0_u64;
        let mut hits = 0_u64;
        for row in rows {
            let key = row_key(&row.id, &row.values, &record.columns, record.id_column);
            if !seen.insert((key.clone(), property.clone())) {
                continue;
            }
            let Some(value) = row.values.get(property) else {
                continue;
            };
            if !is_decimal_measurement(value) {
                continue;
            }
            let Some(odd) = last_digit_odd(value) else {
                continue;
            };
            cells += 1;
            if odd == hmac_bit(&record.operation_id, &key, property) {
                hits += 1;
            }
        }
        if cells < MIN_TRACE_CELLS {
            continue;
        }
        let score = hits as f64 / cells as f64;
        if score < TRACE_SCORE_FLOOR {
            continue;
        }
        let p = binom_tail_half(hits, cells)
            * candidates.max(1) as f64
            * record.columns.len().max(1) as f64;
        if p > TRACE_FAMILY_P {
            continue;
        }
        let better = best.as_ref().is_none_or(|found| score > found.score);
        if better {
            best = Some(TraceMatch {
                receipt_id: record.operation_id.clone(),
                score,
                cells,
                matches: hits,
            });
        }
    }
    best
}

/// P(X >= hits) for X ~ Binomial(cells, 1/2). Hits at or below chance
/// return 1 so a short fragment cannot attribute by luck.
fn binom_tail_half(hits: u64, cells: u64) -> f64 {
    if cells == 0 || hits > cells || hits * 2 <= cells {
        return 1.0;
    }
    let mut log_term = -(cells as f64) * std::f64::consts::LN_2;
    for j in 1..=hits {
        log_term += ((cells - hits + j) as f64).ln() - (j as f64).ln();
    }
    let mut term = log_term.exp();
    let mut sum = term;
    let mut i = hits;
    while i < cells {
        i += 1;
        term *= (cells - i + 1) as f64 / i as f64;
        sum += term;
    }
    sum.min(1.0)
}

fn format_name(format: ExportFormat) -> &'static str {
    format.as_str()
}

fn check_namespace(namespace: &str) -> Result<&str, String> {
    if namespace.is_empty() || namespace.trim() != namespace {
        return Err("namespace must be canonical".into());
    }
    Ok(namespace)
}

fn check_marking(marking: &str) -> Result<&str, String> {
    if marking.is_empty()
        || marking.len() > MAX_MARKING
        || marking.trim() != marking
        || !marking
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/'))
    {
        return Err(format!(
            "marking must be 1 to {MAX_MARKING} letters, digits, '_', '-', '.', ':' or '/'"
        ));
    }
    Ok(marking)
}

fn check_properties(properties: Vec<String>) -> Result<Vec<String>, String> {
    if properties.len() > crate::sekai::data_export::MAX_EXPORT_COLUMNS {
        return Err(format!(
            "at most {} fingerprint properties",
            crate::sekai::data_export::MAX_EXPORT_COLUMNS
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for property in &properties {
        if property.trim().is_empty()
            || property.trim() != property
            || property == "id"
            || property == "external_id"
            || property == OBJECT_CLASSIFICATION_PROPERTY
        {
            return Err(format!("property {property:?} cannot be fingerprinted"));
        }
        if !seen.insert(property) {
            return Err(format!("property {property:?} listed twice"));
        }
    }
    Ok(properties)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::data_export::ExportFormat;

    #[test]
    fn last_decimal_place_moves_by_at_most_one_and_encodes_the_hmac_bit() {
        assert_eq!(set_last_digit_parity("20.50", true), "20.51");
        assert_eq!(set_last_digit_parity("20.50 ", true), "20.51");
        assert_eq!(set_last_digit_parity("20.50", false), "20.50");
        assert_eq!(set_last_digit_parity("20.51", false), "20.50");
        assert_eq!(set_last_digit_parity("20.51", true), "20.51");
        assert_eq!(classify_cell("20.50"), CellKind::Measurement);
        assert_eq!(classify_cell("7"), CellKind::Forbidden("integer"));
        assert_eq!(classify_cell("true"), CellKind::Forbidden("boolean"));
        assert_eq!(
            classify_cell("2026-10-24T12:00:00Z"),
            CellKind::Forbidden("timestamp")
        );
        assert_eq!(classify_cell("north"), CellKind::Forbidden("string"));
        assert_eq!(classify_cell("[redacted]"), CellKind::Absent);
        assert!(check_properties(vec![OBJECT_CLASSIFICATION_PROPERTY.into()]).is_err());
        assert!(check_properties(vec!["id".into()]).is_err());
        assert!((binom_tail_half(8, 8) - 1.0 / 256.0).abs() < 1e-12);
        assert!((binom_tail_half(6, 8) - 37.0 / 256.0).abs() < 1e-12);
        assert_eq!(binom_tail_half(4, 8), 1.0);
    }

    #[test]
    fn two_export_ids_watermark_the_same_row_differently() {
        let encoder = || {
            RowEncoder::new(
                ExportFormat::Csv,
                vec!["title".into(), "temperature".into()],
                true,
            )
            .unwrap()
        };
        let plan = FingerprintPlan {
            by_marking: BTreeMap::from([("internal".into(), vec!["temperature".into()])]),
        };
        let row = || {
            HashMap::from([
                ("title".into(), "alpha".into()),
                ("temperature".into(), "20.50".into()),
                (OBJECT_CLASSIFICATION_PROPERTY.into(), "internal".into()),
            ])
        };
        let encode = |export_id: &str| {
            let mut sink = FingerprintSink::new(export_id.into(), encoder(), Some(plan.clone()));
            let mut bytes = sink.push("t-1", "internal", row()).unwrap();
            bytes.extend(sink.finish());
            String::from_utf8(bytes.concat()).unwrap()
        };
        let alice_row = encode("export-alice");
        let bob_row = encode("export-bob");
        assert_ne!(alice_row, bob_row);
        assert!(alice_row.contains(",alpha,") || alice_row.contains("alpha"));
        assert!(bob_row.contains("alpha"));
        let unmarked = {
            let mut sink =
                FingerprintSink::new("export-alice".into(), encoder(), Some(plan.clone()));
            let mut values = row();
            values.remove(OBJECT_CLASSIFICATION_PROPERTY);
            let mut bytes = sink.push("t-1", "", values).unwrap();
            bytes.extend(sink.finish());
            String::from_utf8(bytes.concat()).unwrap()
        };
        let source = {
            let mut sink = FingerprintSink::new("export-alice".into(), encoder(), None);
            let mut bytes = sink.push("t-1", "internal", row()).unwrap();
            bytes.extend(sink.finish());
            String::from_utf8(bytes.concat()).unwrap()
        };
        assert_eq!(unmarked, source);
        assert!(source.contains("20.50"));
    }

    #[test]
    fn dataset_rows_key_hmac_from_exported_columns_and_skip_redacted_cells() {
        let encoder = || {
            RowEncoder::new(
                ExportFormat::Csv,
                vec!["title".into(), "temperature".into()],
                false,
            )
            .unwrap()
        };
        let plan = FingerprintPlan {
            by_marking: BTreeMap::from([("internal".into(), vec!["temperature".into()])]),
        };
        let mut sink = FingerprintSink::new("export-alice".into(), encoder(), Some(plan.clone()));
        let mut file = encoder().header();
        for n in 0..16 {
            let values = HashMap::from([
                ("title".into(), format!("row-{n}\nnext\r")),
                ("temperature".into(), "20.50".into()),
                ("secret".into(), format!("hidden-{n}")),
            ]);
            for part in sink.push("", "internal", values).unwrap() {
                file.extend(part);
            }
        }
        for part in sink.finish() {
            file.extend(part);
        }
        let text = String::from_utf8(file.clone()).unwrap();
        assert!(!text.contains("hidden-"));
        let record = ExportFingerprintRecord {
            operation_id: "export-alice".into(),
            namespace: "exp".into(),
            columns: vec!["temperature".into()],
            group_size: FINGERPRINT_GROUP_SIZE as u32,
            id_column: false,
        };
        let rows = parse_sample(ExportFormat::Csv, &file).unwrap();
        assert_eq!(rows.len(), 16);
        assert!(rows.iter().any(|row| {
            let title = &row.values["title"];
            title.contains('\n') && title.ends_with('\r')
        }));
        let found = score_sample(&record, &rows, 1).expect("exported columns reconstruct the key");
        assert_eq!(found.receipt_id, "export-alice");
        assert_eq!(found.matches, found.cells);

        let id_encoder = || {
            RowEncoder::new(
                ExportFormat::Csv,
                vec!["id".into(), "temperature".into()],
                false,
            )
            .unwrap()
        };
        let mut id_sink =
            FingerprintSink::new("export-alice".into(), id_encoder(), Some(plan.clone()));
        let mut id_file = id_encoder().header();
        for n in 0..16 {
            let values = HashMap::from([
                ("id".into(), format!("row-{n}")),
                ("temperature".into(), "20.50".into()),
            ]);
            for part in id_sink.push("", "internal", values).unwrap() {
                id_file.extend(part);
            }
        }
        for part in id_sink.finish() {
            id_file.extend(part);
        }
        let id_rows = parse_sample(ExportFormat::Csv, &id_file).unwrap();
        assert!(id_rows.iter().all(|row| !row.id.is_empty()));
        let found = score_sample(&record, &id_rows, 1)
            .expect("a dataset column named id stays in the hashed key");
        assert_eq!(found.matches, found.cells);

        let sparse = || {
            RowEncoder::new(
                ExportFormat::Csv,
                vec!["title".into(), "note".into(), "temperature".into()],
                false,
            )
            .unwrap()
        };
        let mut missing = FingerprintSink::new("export-alice".into(), sparse(), Some(plan.clone()));
        let mut missing_file = sparse().header();
        for n in 0..16 {
            let values = HashMap::from([
                ("note".into(), format!("n-{n}")),
                ("temperature".into(), "20.50".into()),
            ]);
            for part in missing.push("", "internal", values).unwrap() {
                missing_file.extend(part);
            }
        }
        for part in missing.finish() {
            missing_file.extend(part);
        }
        let missing_rows = parse_sample(ExportFormat::Csv, &missing_file).unwrap();
        assert!(missing_rows.iter().any(|row| {
            row.values
                .get("title")
                .is_some_and(|title| title.is_empty())
        }));
        let found = score_sample(&record, &missing_rows, 1)
            .expect("a missing csv cell and an absent map key hash the same");
        assert_eq!(found.matches, found.cells);

        let only =
            || RowEncoder::new(ExportFormat::Csv, vec!["temperature".into()], false).unwrap();
        let mut only_sink = FingerprintSink::new("export-alice".into(), only(), Some(plan.clone()));
        let mut only_file = only().header();
        for n in 0..16 {
            let values = HashMap::from([("temperature".into(), format!("{}.50", 10 + n))]);
            for part in only_sink.push("", "internal", values).unwrap() {
                only_file.extend(part);
            }
        }
        for part in only_sink.finish() {
            only_file.extend(part);
        }
        let only_rows = parse_sample(ExportFormat::Csv, &only_file).unwrap();
        let found = score_sample(&record, &only_rows, 1)
            .expect("a measurements-only dataset still keys rows by the unwatermarked stem");
        assert_eq!(found.matches, found.cells);

        let mut repeated =
            FingerprintSink::new("export-alice".into(), encoder(), Some(plan.clone()));
        let mut repeated_file = encoder().header();
        for _ in 0..16 {
            let values = HashMap::from([
                ("title".into(), "alpha".into()),
                ("temperature".into(), "20.50".into()),
            ]);
            for part in repeated.push("", "internal", values).unwrap() {
                repeated_file.extend(part);
            }
        }
        for part in repeated.finish() {
            repeated_file.extend(part);
        }
        let repeated_rows = parse_sample(ExportFormat::Csv, &repeated_file).unwrap();
        assert!(
            score_sample(&record, &repeated_rows, 1).is_none(),
            "identical dataset rows count as one hmac cell"
        );

        let mut redacted = FingerprintSink::new("export-alice".into(), encoder(), Some(plan));
        let mut bytes = redacted
            .push(
                "",
                "internal",
                HashMap::from([
                    ("title".into(), "alpha".into()),
                    ("temperature".into(), "[redacted]".into()),
                ]),
            )
            .unwrap();
        bytes.extend(redacted.finish());
        let text = String::from_utf8(bytes.concat()).unwrap();
        assert!(text.contains("[redacted]"));
        assert!(text.contains("alpha"));
    }

    #[test]
    fn default_off_exports_are_byte_identical_and_a_sample_traces() {
        use crate::sekai::audit::DecisionFilter;
        use crate::sekai::data_export::{ExportReceipt, ExportSource};

        let db = crate::db::runtime_db::RuntimeDb::memory();
        let ns = format!(
            "fp-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        put_fingerprint_policy(&db, &ns, "internal", vec!["temperature".into()], "admin", 1)
            .unwrap();
        assert!(
            db.list_decisions(&DecisionFilter {
                actor: Some("admin".into()),
                action: Some("export_fingerprint_policy".into()),
                target_id: Some(format!("{ns}:internal")),
                after: 0,
                limit: 8,
                offset: 0,
            })
            .unwrap()
            .iter()
            .any(|decision| decision.outcome == "on")
        );
        let encoder = || {
            RowEncoder::new(
                ExportFormat::Csv,
                vec!["title".into(), "temperature".into()],
                true,
            )
            .unwrap()
        };
        let plan = namespace_plan(&db, &ns).unwrap();
        let rows: Vec<(String, HashMap<String, String>)> = (0..160)
            .map(|n| {
                (
                    format!("t-{n:05}"),
                    HashMap::from([
                        ("title".into(), "alpha".into()),
                        ("temperature".into(), "20.50".into()),
                    ]),
                )
            })
            .collect();
        let run = |actor: &str| {
            let source = ExportSource {
                namespace: ns.clone(),
                source_kind: "object_set",
                source_id: "Ticket".into(),
                source_version: "sha256:q".into(),
                definition_digest: "sha256:d".into(),
                format: ExportFormat::Csv,
                columns: vec!["title".into(), "temperature".into()],
                granted_via: actor.into(),
                fingerprint_properties: vec!["temperature".into()],
                fingerprint_group_size: FINGERPRINT_GROUP_SIZE as u32,
            };
            let receipt = ExportReceipt::begin(db.clone(), actor, &source, 10).unwrap();
            let id = receipt.operation_id().to_string();
            record_export_fingerprint(
                &db,
                &ExportFingerprintRecord {
                    operation_id: id.clone(),
                    namespace: ns.clone(),
                    columns: vec!["temperature".into()],
                    group_size: FINGERPRINT_GROUP_SIZE as u32,
                    id_column: true,
                },
            )
            .unwrap();
            let mut sink = FingerprintSink::new(id.clone(), encoder(), plan.clone());
            let mut file = encoder().header();
            for (row_id, values) in &rows {
                for part in sink.push(row_id, "internal", values.clone()).unwrap() {
                    file.extend(part);
                }
            }
            for part in sink.finish() {
                file.extend(part);
            }
            receipt.complete(11).unwrap();
            (id, file)
        };
        let (alice_id, alice_file) = run("alice");
        let (bob_id, bob_file) = run("bob");
        assert_ne!(alice_file, bob_file);
        assert!(String::from_utf8_lossy(&alice_file).contains("alpha"));
        assert!(String::from_utf8_lossy(&bob_file).contains("alpha"));
        let off = {
            let mut sink = FingerprintSink::new("export-off".into(), encoder(), None);
            let mut file = encoder().header();
            for (row_id, values) in &rows {
                for part in sink.push(row_id, "internal", values.clone()).unwrap() {
                    file.extend(part);
                }
            }
            file
        };
        assert!(String::from_utf8_lossy(&off).contains("20.50"));
        let sample: Vec<u8> = {
            let text = String::from_utf8(alice_file.clone()).unwrap();
            let mut lines: Vec<&str> = text.lines().collect();
            let header = lines.remove(0);
            let take = (lines.len() / 10).max(8);
            let mut out = String::from(header);
            out.push('\n');
            for line in lines.into_iter().take(take) {
                out.push_str(line);
                out.push('\n');
            }
            out.into_bytes()
        };
        let hits = trace_export(&db, &ns, ExportFormat::Csv, &sample, "admin", 20, true).unwrap();
        assert_eq!(hits[0].receipt_id, alice_id);
        assert!(
            hits.iter()
                .all(|hit| hit.receipt_id != bob_id || hit.score < hits[0].score)
        );
        let denied =
            trace_export(&db, &ns, ExportFormat::Csv, &sample, "eve", 21, false).unwrap_err();
        assert_eq!(denied, crate::sekai::data_export::EXPORT_DENIED);
        let decisions = db
            .list_decisions(&DecisionFilter {
                actor: Some("eve".into()),
                action: Some("trace_export".into()),
                target_id: Some(ns.clone()),
                after: 0,
                limit: 8,
                offset: 0,
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|decision| decision.outcome == "denied")
        );
        let invalid = trace_export(&db, &ns, ExportFormat::Csv, b"", "admin", 21, true)
            .expect_err("empty sample");
        assert!(invalid.contains("sample must be"));
        let invalid_decisions = db
            .list_decisions(&DecisionFilter {
                actor: Some("admin".into()),
                action: Some("trace_export".into()),
                target_id: Some(ns.clone()),
                after: 0,
                limit: 16,
                offset: 0,
            })
            .unwrap();
        assert!(
            invalid_decisions
                .iter()
                .any(|decision| decision.outcome == "invalid")
        );
    }

    #[test]
    fn two_marking_union_scores_the_best_listed_property() {
        let encoder = || {
            RowEncoder::new(
                ExportFormat::Csv,
                vec!["title".into(), "temperature".into(), "pressure".into()],
                true,
            )
            .unwrap()
        };
        let plan = FingerprintPlan {
            by_marking: BTreeMap::from([
                ("internal".into(), vec!["temperature".into()]),
                ("restricted".into(), vec!["pressure".into()]),
            ]),
        };
        let mut sink = FingerprintSink::new("export-alice".into(), encoder(), Some(plan));
        let mut file = encoder().header();
        for n in 0..16 {
            let values = HashMap::from([
                ("title".into(), format!("row-{n}")),
                ("temperature".into(), "20.50".into()),
                ("pressure".into(), "1.00".into()),
            ]);
            for part in sink.push(&format!("t-{n}"), "internal", values).unwrap() {
                file.extend(part);
            }
        }
        for part in sink.finish() {
            file.extend(part);
        }
        let record = ExportFingerprintRecord {
            operation_id: "export-alice".into(),
            namespace: "exp".into(),
            columns: vec!["pressure".into(), "temperature".into()],
            group_size: FINGERPRINT_GROUP_SIZE as u32,
            id_column: true,
        };
        let rows = parse_sample(ExportFormat::Csv, &file).unwrap();
        let found = score_sample(&record, &rows, 1)
            .expect("internal rows still trace when the union lists another property");
        assert_eq!(found.receipt_id, "export-alice");
        assert_eq!(found.matches, found.cells);
        assert!(found.score >= TRACE_SCORE_FLOOR);
    }

    #[test]
    fn mixed_unmarked_rows_still_trace_from_the_marked_majority() {
        let encoder = || {
            RowEncoder::new(
                ExportFormat::Csv,
                vec!["title".into(), "temperature".into()],
                true,
            )
            .unwrap()
        };
        let plan = FingerprintPlan {
            by_marking: BTreeMap::from([("internal".into(), vec!["temperature".into()])]),
        };
        let mut sink = FingerprintSink::new("export-alice".into(), encoder(), Some(plan));
        let mut file = encoder().header();
        for n in 0..64 {
            let marking = if n < 48 { "internal" } else { "" };
            let values = HashMap::from([
                ("title".into(), format!("row-{n}")),
                ("temperature".into(), "20.50".into()),
            ]);
            for part in sink.push(&format!("t-{n}"), marking, values).unwrap() {
                file.extend(part);
            }
        }
        for part in sink.finish() {
            file.extend(part);
        }
        let record = ExportFingerprintRecord {
            operation_id: "export-alice".into(),
            namespace: "exp".into(),
            columns: vec!["temperature".into()],
            group_size: FINGERPRINT_GROUP_SIZE as u32,
            id_column: true,
        };
        let rows = parse_sample(ExportFormat::Csv, &file).unwrap();
        let found = score_sample(&record, &rows, 1)
            .expect("unmarked decimals in the same column do not hide a marked majority");
        assert_eq!(found.receipt_id, "export-alice");
        assert!(found.score >= TRACE_SCORE_FLOOR);
        assert!(found.cells >= MIN_TRACE_CELLS);
    }
}
