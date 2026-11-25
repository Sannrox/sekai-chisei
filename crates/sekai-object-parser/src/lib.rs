//! Parses one CSV or Parquet object into JSON rows, for the
//! `object_storage` connector type's bounded worker (`main.rs`).
//!
//! The worker protocol: the parent runs `sekai-object-parser <csv|parquet>
//! <max_rows>` with an empty environment, writes the object's bytes to
//! stdin and closes it. On success the worker writes one JSON object per
//! line to stdout and exits 0. On a refusal it writes one reason from
//! [`Refusal`] to stderr and exits 2. The parent bounds the input, the
//! output and the wall time, and treats anything else as a refusal too.

use std::collections::HashSet;

use bytes::Bytes;
use parquet::file::reader::{FileReader, SerializedFileReader};
use serde_json::{Map, Value};

/// The most input bytes the worker reads; the parent sends less.
pub const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// The most bytes a Parquet object's row groups may decode to, so a small
/// compressed object cannot expand without bound.
pub const MAX_DECODED_BYTES: i64 = 64 * 1024 * 1024;

/// Why an object was refused. The text is the reason the worker reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    NotUtf8,
    TooManyRows,
    TooLarge,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotUtf8 => "not_utf8",
            Self::TooManyRows => "too_many_rows",
            Self::TooLarge => "too_large",
        }
    }
}

/// The formats the worker parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Parquet,
}

impl Format {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "csv" => Some(Self::Csv),
            "parquet" => Some(Self::Parquet),
            _ => None,
        }
    }
}

pub type Row = Map<String, Value>;

/// The rows of `bytes`, at most `max_rows` of them.
pub fn parse(format: Format, bytes: &[u8], max_rows: usize) -> Result<Vec<Row>, Refusal> {
    match format {
        Format::Csv => csv_rows(bytes, max_rows),
        Format::Parquet => parquet_rows(bytes, max_rows),
    }
}

/// A header line naming distinct, non-empty columns, then rows of exactly
/// that many fields. Every value is a string; CSV carries no types.
fn csv_rows(bytes: &[u8], max_rows: usize) -> Result<Vec<Row>, Refusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    // The reader takes a quote left open at the end as a field running to
    // the end, which would hide a cut-off object.
    if text.contains('\0') || ends_inside_quotes(text) {
        return Err(Refusal::Malformed);
    }
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|_| Refusal::Malformed)?
        .iter()
        .map(str::to_string)
        .collect();
    distinct_names(headers.iter().map(String::as_str))?;
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|_| Refusal::Malformed)?;
        if rows.len() == max_rows {
            return Err(Refusal::TooManyRows);
        }
        rows.push(
            headers
                .iter()
                .zip(record.iter())
                .map(|(name, value)| (name.clone(), Value::String(value.into())))
                .collect(),
        );
    }
    Ok(rows)
}

/// Whether `text` ends inside a quoted field: a quote opens a field only
/// at its start, and inside one a doubled quote is an escaped quote.
fn ends_inside_quotes(text: &str) -> bool {
    let mut quoted = false;
    let mut field_start = true;
    let mut chars = text.chars().peekable();
    while let Some(char) = chars.next() {
        if quoted {
            if char == '"' && chars.next_if_eq(&'"').is_none() {
                quoted = false;
            }
        } else {
            quoted = char == '"' && field_start;
            field_start = matches!(char, ',' | '\n' | '\r');
        }
    }
    quoted
}

/// Each row's top-level columns as JSON values: numbers, booleans and
/// strings as themselves, dates, times and decimals as text, binary as
/// base64, nested values as arrays and objects.
fn parquet_rows(bytes: &[u8], max_rows: usize) -> Result<Vec<Row>, Refusal> {
    let reader =
        SerializedFileReader::new(Bytes::copy_from_slice(bytes)).map_err(|_| Refusal::Malformed)?;
    let metadata = reader.metadata();
    let declared = metadata.file_metadata().num_rows();
    if usize::try_from(declared).map_or(true, |rows| rows > max_rows) {
        return Err(Refusal::TooManyRows);
    }
    let decoded = metadata.row_groups().iter().try_fold(0i64, |total, group| {
        total.checked_add(group.total_byte_size().max(0))
    });
    if decoded.is_none_or(|bytes| bytes > MAX_DECODED_BYTES) {
        return Err(Refusal::TooLarge);
    }
    let schema = metadata.file_metadata().schema_descr();
    distinct_names(
        schema
            .root_schema()
            .get_fields()
            .iter()
            .map(|field| field.name()),
    )?;
    let mut rows = Vec::new();
    for row in reader.get_row_iter(None).map_err(|_| Refusal::Malformed)? {
        let row = row.map_err(|_| Refusal::Malformed)?;
        // The declared count is the file's word; the rows read are checked
        // as well.
        if rows.len() == max_rows {
            return Err(Refusal::TooManyRows);
        }
        match row.to_json_value() {
            Value::Object(row) => rows.push(row),
            _ => return Err(Refusal::Malformed),
        }
    }
    Ok(rows)
}

fn distinct_names<'a>(names: impl Iterator<Item = &'a str>) -> Result<(), Refusal> {
    let mut seen = HashSet::new();
    let mut any = false;
    for name in names {
        any = true;
        if name.is_empty() || !seen.insert(name) {
            return Err(Refusal::Malformed);
        }
    }
    if any { Ok(()) } else { Err(Refusal::Malformed) }
}

#[cfg(test)]
mod tests;
