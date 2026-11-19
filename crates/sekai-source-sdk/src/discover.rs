//! Connection check and schema discovery for source adapters (#1408).
//!
//! `check` proves connectivity and credentials without reading records.
//! `discover` lists what a source offers: record kinds, typed columns, key
//! candidates, and optional per-column profile hints. A discovery only drafts
//! source-type descriptors (ADR 0060) and onboarding input; admission and
//! sensitivity marking stay reviewable control-plane acts.
//!
//! `sample_rows` is optional on the same contract: a plane-capped peek at
//! values for one record kind, read with the adapter's credentials. Sources
//! that cannot sample answer [`DiscoverySample::Unsupported`]. Samples are
//! never part of the discovery document, so they are not persisted with it.
//!
//! [`attach_references`] adds reference candidates between record kinds
//! (#2294): the references a source declares, plus single-column references
//! inferred from the bounded samples. It makes at most one
//! [`SourceInspector::declared_references`] call and one
//! [`SourceInspector::sample_rows`] call per record kind, so the cost does not
//! grow with the number of column pairs. Sample values are compared in memory;
//! only counts leave this module.
//!
//! [`attach_value_findings`] adds value-shape findings (#2295): hints computed
//! from the same bounded samples, one `sample_rows` call per record kind. A
//! finding names a column, a stable code, the rows it saw and the rows that
//! matched, and the formats involved. It never carries a value, and the
//! absence of a finding says nothing about the rest of the column.

use crate::contract::{MAX_SOURCE_IDENTIFIER_BYTES, contains_secret_like_text};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_DISCOVERY_VERSION: &str = "sekai.source-discovery/v1";
pub const MAX_DISCOVERED_RECORD_KINDS: usize = 1024;
pub const MAX_DISCOVERED_COLUMNS: usize = 1024;
/// Plane-owned sample size. Callers cannot request a larger peek.
pub const MAX_DISCOVERY_SAMPLE_ROWS: usize = 8;
/// Profile ratios are basis points so discoveries stay exact and comparable.
pub const PROFILE_RATIO_SCALE: u16 = 10_000;
/// Plane-owned floor for inferred references: the share of non-null sampled
/// values, in basis points, that must appear among the target's sampled keys.
pub const MIN_INFERRED_REFERENCE_MATCH_BP: u16 = 8_000;

/// Why a source could not be checked or discovered. Value-free by design:
/// diagnostics never carry credentials, hosts, or remote response bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFailure {
    Unreachable,
    AuthFailed,
    PermissionMissing,
}

impl std::fmt::Display for ConnectionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unreachable => "source is unreachable",
            Self::AuthFailed => "source rejected the credentials",
            Self::PermissionMissing => "source credentials lack a required permission",
        })
    }
}

impl std::error::Error for ConnectionFailure {}

/// Source-owned check and discovery, next to the snapshot and change-feed
/// readers. Implementations hold their own credentials.
pub trait SourceInspector {
    /// Validate connectivity and credentials. Must not read records.
    fn check(&mut self) -> Result<(), ConnectionFailure>;
    /// List record kinds in ascending `record_kind` order. Must be
    /// deterministic for an unchanged source.
    fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure>;
    /// Bounded peek at values for one discovered record kind. The size cap
    /// is plane-owned; a source that cannot sample returns
    /// [`DiscoverySample::Unsupported`].
    fn sample_rows(&mut self, _record_kind: &str) -> Result<DiscoverySample, ConnectionFailure> {
        Ok(DiscoverySample::Unsupported)
    }
    /// References the source itself declares between its record kinds. A
    /// source that cannot report them keeps the default.
    fn declared_references(&mut self) -> Result<DeclaredReferences, ConnectionFailure> {
        Ok(DeclaredReferences::Unsupported)
    }
}

/// References a source declares, or a typed refusal when it cannot report them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeclaredReferences {
    Unsupported,
    Declared(Vec<DeclaredReference>),
}

/// One source-declared reference. `target_key` must be a key candidate of
/// `target_record_kind` and as long as `columns`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredReference {
    pub record_kind: String,
    pub columns: Vec<String>,
    pub target_record_kind: String,
    pub target_key: Vec<String>,
}

/// Values from one record kind, or a typed refusal when the source cannot
/// sample. Never stored on [`SourceDiscovery`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoverySample {
    Unsupported,
    Rows {
        cells: Vec<BTreeMap<String, String>>,
    },
}

/// Truncate a sample to [`MAX_DISCOVERY_SAMPLE_ROWS`]. Adapters that ignore
/// the constant still cannot return a larger peek through this helper.
pub fn cap_discovery_sample(sample: DiscoverySample) -> DiscoverySample {
    match sample {
        DiscoverySample::Rows { mut cells } => {
            cells.truncate(MAX_DISCOVERY_SAMPLE_ROWS);
            DiscoverySample::Rows { cells }
        }
        other => other,
    }
}

/// Optional per-column hints computed by the connector, never by the plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnProfileHint {
    pub distinct_ratio_bp: u16,
    pub null_ratio_bp: u16,
    pub possibly_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredColumn {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    #[serde(default)]
    pub profile: Option<ColumnProfileHint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredRecordKind {
    pub record_kind: String,
    /// The source's own schema revision; a change is declared drift.
    pub schema_revision: String,
    /// Columns in source order.
    pub columns: Vec<DiscoveredColumn>,
    /// Each candidate is an ordered column list; composite keys have several.
    /// Empty when the record kind has no usable key.
    pub key_candidates: Vec<Vec<String>>,
    /// Reference candidates, ordered by columns then target. Empty until
    /// [`attach_references`] runs; older consumers ignore it.
    #[serde(default)]
    pub references: Vec<ReferenceCandidate>,
    /// Value-shape findings, ordered by column then code. Empty until
    /// [`attach_value_findings`] runs; older consumers ignore it.
    #[serde(default)]
    pub value_findings: Vec<ValueShapeFinding>,
}

/// What a sampled column looks like. The strings from [`Self::as_str`] are
/// stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValueShapeCode {
    MixedTemporalFormat,
    TemporalAsText,
    ValueVariants,
    NullableReference,
    SoftDeleteCandidate,
    NumericAsText,
}

impl ValueShapeCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MixedTemporalFormat => "mixed_temporal_format",
            Self::TemporalAsText => "temporal_as_text",
            Self::ValueVariants => "value_variants",
            Self::NullableReference => "nullable_reference",
            Self::SoftDeleteCandidate => "soft_delete_candidate",
            Self::NumericAsText => "numeric_as_text",
        }
    }
}

/// One hint about a column, from the bounded sample. Counts and format names
/// only; `sampled` says how many rows it saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueShapeFinding {
    pub column: String,
    pub code: ValueShapeCode,
    /// Sampled rows of the record kind.
    pub sampled: u32,
    /// Sampled rows the finding rests on: parsed values, distinct spellings
    /// that collapse, or rows with a missing value.
    pub matched: u32,
    /// Temporal format names, in ascending order; empty for other codes.
    #[serde(with = "formats_serde")]
    pub formats: Vec<&'static str>,
}

/// Why a reference candidate is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReferenceBasis {
    /// The source declares the reference.
    Declared,
    /// No declaration; sampled values and names suggest it.
    Inferred,
}

/// Counts from the bounded sample behind a candidate. No values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceEvidence {
    /// Sampled rows of the referencing record kind.
    pub sampled: u32,
    /// Sampled rows whose referencing columns match a sampled target key.
    pub matched: u32,
    /// Sampled rows with a missing referencing value, in basis points.
    pub null_ratio_bp: u16,
    /// Whether the source allows the referencing columns to be null.
    pub nullable: bool,
}

/// Columns of one record kind that point at a key candidate of another (or
/// the same) record kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCandidate {
    pub columns: Vec<String>,
    pub target_record_kind: String,
    pub target_key: Vec<String>,
    pub basis: ReferenceBasis,
    /// `None` when the source cannot sample the record kind.
    pub evidence: Option<ReferenceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDiscovery {
    pub contract_version: String,
    pub source: String,
    pub record_kinds: Vec<DiscoveredRecordKind>,
}

/// Reviewable input for `RegisterSourceTypeDescriptor`: one record kind at one
/// schema revision. The plane computes the digest when it admits the draft, and
/// still rejects code-owned GitHub Issue/PullRequest names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorDraft {
    pub source: String,
    pub record_kind: String,
    pub schema_revision: String,
}

impl SourceDiscovery {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != SOURCE_DISCOVERY_VERSION {
            return Err("unsupported source discovery contract".into());
        }
        require_token("source", &self.source)?;
        if self.record_kinds.len() > MAX_DISCOVERED_RECORD_KINDS {
            return Err("discovery lists too many record kinds".into());
        }
        for pair in self.record_kinds.windows(2) {
            if pair[0].record_kind >= pair[1].record_kind {
                return Err("record kinds must be unique and in ascending order".into());
            }
        }
        self.record_kinds
            .iter()
            .try_for_each(validate_record_kind)?;
        self.record_kinds
            .iter()
            .try_for_each(|kind| self.validate_references(kind))
    }

    fn validate_references(&self, kind: &DiscoveredRecordKind) -> Result<(), String> {
        let mut seen = BTreeSet::new();
        for reference in &kind.references {
            let target = self
                .record_kinds
                .iter()
                .find(|target| target.record_kind == reference.target_record_kind)
                .ok_or("reference targets an unknown record kind")?;
            let columns_exist = reference
                .columns
                .iter()
                .all(|name| kind.columns.iter().any(|column| &column.name == name));
            if reference.columns.is_empty()
                || !columns_exist
                || reference.columns.len() != reference.target_key.len()
                || !target.key_candidates.contains(&reference.target_key)
            {
                return Err(
                    "reference must pair existing columns with a target key candidate".into(),
                );
            }
            if !seen.insert((&reference.columns, &reference.target_record_kind)) {
                return Err("references must be unique".into());
            }
        }
        Ok(())
    }

    /// One draft per record kind, in discovery order. Mechanical conversion
    /// only; the catalog still refuses code-owned GitHub kinds.
    pub fn descriptor_drafts(&self) -> Result<Vec<DescriptorDraft>, String> {
        self.validate()?;
        Ok(self
            .record_kinds
            .iter()
            .map(|kind| DescriptorDraft {
                source: self.source.clone(),
                record_kind: kind.record_kind.clone(),
                schema_revision: kind.schema_revision.clone(),
            })
            .collect())
    }
}

/// Whether the source reported references at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceSupport {
    /// The source neither declares references nor samples values.
    Unsupported,
    Attached,
}

/// Fill `references` on every record kind of `discovery`: the declared
/// references, then single-column references inferred from the samples whose
/// names are compatible and whose sampled values match at least
/// [`MIN_INFERRED_REFERENCE_MATCH_BP`] of the target's sampled keys. The
/// result is deterministic for unchanged data.
pub fn attach_references<S: SourceInspector>(
    inspector: &mut S,
    discovery: &mut SourceDiscovery,
) -> Result<ReferenceSupport, ConnectionFailure> {
    discovery
        .validate()
        .map_err(|_| ConnectionFailure::PermissionMissing)?;
    let declared = match inspector.declared_references()? {
        DeclaredReferences::Declared(declared) => Some(declared),
        _ => None,
    };
    let mut samples = BTreeMap::new();
    for kind in &discovery.record_kinds {
        if let DiscoverySample::Rows { cells } =
            cap_discovery_sample(inspector.sample_rows(&kind.record_kind)?)
        {
            samples.insert(kind.record_kind.clone(), cells);
        }
    }
    if declared.is_none() && samples.is_empty() {
        return Ok(ReferenceSupport::Unsupported);
    }

    let mut found: Vec<(usize, ReferenceCandidate)> = Vec::new();
    for reference in declared.iter().flatten() {
        if let Some(index) = discovery
            .record_kinds
            .iter()
            .position(|kind| kind.record_kind == reference.record_kind)
        {
            let nullable = nullable(&discovery.record_kinds[index], &reference.columns);
            let evidence = samples
                .get(&reference.record_kind)
                .zip(samples.get(&reference.target_record_kind))
                .map(|(rows, targets)| {
                    evidence(
                        rows,
                        &reference.columns,
                        targets,
                        &reference.target_key,
                        nullable,
                    )
                });
            found.push((
                index,
                ReferenceCandidate {
                    columns: reference.columns.clone(),
                    target_record_kind: reference.target_record_kind.clone(),
                    target_key: reference.target_key.clone(),
                    basis: ReferenceBasis::Declared,
                    evidence,
                },
            ));
        }
    }
    for (index, kind) in discovery.record_kinds.iter().enumerate() {
        let Some(rows) = samples.get(&kind.record_kind) else {
            continue;
        };
        for column in &kind.columns {
            let own_key = kind
                .key_candidates
                .iter()
                .any(|key| key == std::slice::from_ref(&column.name));
            if own_key {
                continue;
            }
            for target in &discovery.record_kinds {
                let Some(targets) = samples.get(&target.record_kind) else {
                    continue;
                };
                for key in target.key_candidates.iter().filter(|key| key.len() == 1) {
                    if !name_compatible(&column.name, &target.record_kind, &key[0]) {
                        continue;
                    }
                    let columns = vec![column.name.clone()];
                    let evidence = evidence(rows, &columns, targets, key, column.nullable);
                    let present = evidence.sampled - nulls(rows, &columns);
                    if evidence.matched == 0
                        || u64::from(evidence.matched) * u64::from(PROFILE_RATIO_SCALE)
                            < u64::from(present) * u64::from(MIN_INFERRED_REFERENCE_MATCH_BP)
                    {
                        continue;
                    }
                    found.push((
                        index,
                        ReferenceCandidate {
                            columns,
                            target_record_kind: target.record_kind.clone(),
                            target_key: key.clone(),
                            basis: ReferenceBasis::Inferred,
                            evidence: Some(evidence),
                        },
                    ));
                }
            }
        }
    }
    for kind in &mut discovery.record_kinds {
        kind.references.clear();
    }
    for (index, candidate) in found {
        let references = &mut discovery.record_kinds[index].references;
        // A declaration wins over an inference of the same reference.
        if !references.iter().any(|known| {
            known.columns == candidate.columns
                && known.target_record_kind == candidate.target_record_kind
        }) {
            references.push(candidate);
        }
    }
    for kind in &mut discovery.record_kinds {
        kind.references.sort_by(|a, b| {
            (&a.columns, &a.target_record_kind).cmp(&(&b.columns, &b.target_record_kind))
        });
    }
    Ok(ReferenceSupport::Attached)
}

/// Whether the source sampled at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueShapeSupport {
    /// No record kind could be sampled, so no finding was computed.
    SamplesUnavailable,
    Attached,
}

/// Fill `value_findings` on every record kind of `discovery` from the bounded
/// samples. Run [`attach_references`] first to get `nullable_reference`
/// findings. Deterministic for unchanged data.
pub fn attach_value_findings<S: SourceInspector>(
    inspector: &mut S,
    discovery: &mut SourceDiscovery,
) -> Result<ValueShapeSupport, ConnectionFailure> {
    let mut sampled_any = false;
    for kind in &mut discovery.record_kinds {
        kind.value_findings.clear();
        let DiscoverySample::Rows { cells } =
            cap_discovery_sample(inspector.sample_rows(&kind.record_kind)?)
        else {
            continue;
        };
        sampled_any = true;
        let mut findings = Vec::new();
        for column in &kind.columns {
            column_findings(column, &cells, &mut findings);
        }
        for reference in &kind.references {
            let [column] = reference.columns.as_slice() else {
                continue;
            };
            let missing = nulls(&cells, &reference.columns);
            if missing > 0 && (missing as usize) < cells.len() {
                findings.push(ValueShapeFinding {
                    column: column.clone(),
                    code: ValueShapeCode::NullableReference,
                    sampled: cells.len() as u32,
                    matched: missing,
                    formats: Vec::new(),
                });
            }
        }
        findings.sort_by(|a, b| (&a.column, a.code).cmp(&(&b.column, b.code)));
        kind.value_findings = findings;
    }
    Ok(if sampled_any {
        ValueShapeSupport::Attached
    } else {
        ValueShapeSupport::SamplesUnavailable
    })
}

fn column_findings(
    column: &DiscoveredColumn,
    rows: &[BTreeMap<String, String>],
    findings: &mut Vec<ValueShapeFinding>,
) {
    let sampled = rows.len() as u32;
    let values: Vec<&str> = rows
        .iter()
        .filter_map(|row| cell(row, &column.name))
        .collect();
    let missing = sampled - values.len() as u32;
    let finding = |code, matched, formats| ValueShapeFinding {
        column: column.name.clone(),
        code,
        sampled,
        matched,
        formats,
    };
    let data_type = column.data_type.to_ascii_lowercase();
    let is_text = ["char", "text", "string"]
        .iter()
        .any(|word| data_type.contains(word));
    let is_temporal = ["date", "time"].iter().any(|word| data_type.contains(word));
    let is_boolean = data_type.contains("bool");

    if is_text && !values.is_empty() {
        let formats: Vec<Option<&'static str>> =
            values.iter().map(|value| temporal_format(value)).collect();
        let parsed: BTreeSet<&'static str> = formats.iter().flatten().copied().collect();
        let temporal_rows = formats.iter().flatten().count() as u32;
        if parsed.len() > 1 {
            findings.push(finding(
                ValueShapeCode::MixedTemporalFormat,
                temporal_rows,
                parsed.into_iter().collect(),
            ));
        } else if parsed.len() == 1 && temporal_rows as usize == values.len() {
            findings.push(finding(
                ValueShapeCode::TemporalAsText,
                temporal_rows,
                parsed.into_iter().collect(),
            ));
        } else if values
            .iter()
            .all(|value| value.parse::<f64>().is_ok_and(f64::is_finite))
        {
            findings.push(finding(
                ValueShapeCode::NumericAsText,
                values.len() as u32,
                Vec::new(),
            ));
        } else if parsed.is_empty() {
            let raw: BTreeSet<&str> = values.iter().copied().collect();
            let folded: BTreeSet<String> = raw
                .iter()
                .map(|value| value.trim().to_lowercase())
                .collect();
            if folded.len() < raw.len() {
                findings.push(finding(
                    ValueShapeCode::ValueVariants,
                    raw.len() as u32,
                    Vec::new(),
                ));
            }
        }
    }
    let marker = ["delete", "removed", "archived"]
        .iter()
        .any(|word| column.name.to_ascii_lowercase().contains(word));
    let mostly_missing = u64::from(missing) * 2 >= u64::from(sampled) && sampled > 0;
    if column.nullable && marker && ((is_temporal && mostly_missing) || is_boolean) {
        findings.push(finding(
            ValueShapeCode::SoftDeleteCandidate,
            missing,
            Vec::new(),
        ));
    }
}

const TEMPORAL_FORMAT_NAMES: &[&str] = &[
    "iso_date",
    "dotted_date",
    "slash_date",
    "time",
    "iso_datetime",
];

/// Wire form of [`ValueShapeFinding::formats`]: [`TEMPORAL_FORMAT_NAMES`].
/// Unknown names fail closed so a stored discovery cannot invent a format
/// the drafter would not understand.
mod formats_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    const KNOWN: &[&str] = super::TEMPORAL_FORMAT_NAMES;

    pub(super) fn serialize<S: Serializer>(
        formats: &[&'static str],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(formats.iter().copied())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<&'static str>, D::Error> {
        let names = Vec::<String>::deserialize(deserializer)?;
        names
            .into_iter()
            .map(|name| {
                KNOWN
                    .iter()
                    .copied()
                    .find(|known| *known == name)
                    .ok_or_else(|| {
                        serde::de::Error::custom(format!("unknown value-shape format {name}"))
                    })
            })
            .collect()
    }
}

/// The temporal format of a value, or `None`. Shapes are checked by digit
/// layout and plausible month and day ranges, not by a calendar.
fn temporal_format(value: &str) -> Option<&'static str> {
    let digits_at = |range: std::ops::Range<usize>| -> Option<u32> {
        value
            .get(range)?
            .parse()
            .ok()
            .filter(|_| value.is_char_boundary(0))
    };
    let shape: String = value
        .chars()
        .map(|c| if c.is_ascii_digit() { '9' } else { c })
        .collect();
    let plausible = |month: Option<u32>, day: Option<u32>| {
        matches!(month, Some(1..=12)) && matches!(day, Some(1..=31))
    };
    match shape.as_str() {
        "9999-99-99" if plausible(digits_at(5..7), digits_at(8..10)) => Some("iso_date"),
        "99.99.9999" if plausible(digits_at(3..5), digits_at(0..2)) => Some("dotted_date"),
        "99/99/9999" if plausible(digits_at(0..2), digits_at(3..5)) => Some("slash_date"),
        "99:99" | "99:99:99" => Some("time"),
        _ if (shape.starts_with("9999-99-99T") || shape.starts_with("9999-99-99 "))
            && shape[11..].starts_with("99:99")
            && plausible(digits_at(5..7), digits_at(8..10)) =>
        {
            Some("iso_datetime")
        }
        _ => None,
    }
}

fn nullable(kind: &DiscoveredRecordKind, columns: &[String]) -> bool {
    kind.columns
        .iter()
        .any(|column| column.nullable && columns.contains(&column.name))
}

/// A cell is missing when the column is absent or empty.
fn cell<'a>(row: &'a BTreeMap<String, String>, column: &str) -> Option<&'a str> {
    row.get(column)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn tuple<'a>(row: &'a BTreeMap<String, String>, columns: &[String]) -> Option<Vec<&'a str>> {
    columns.iter().map(|column| cell(row, column)).collect()
}

fn nulls(rows: &[BTreeMap<String, String>], columns: &[String]) -> u32 {
    rows.iter()
        .filter(|row| tuple(row, columns).is_none())
        .count() as u32
}

fn evidence(
    rows: &[BTreeMap<String, String>],
    columns: &[String],
    targets: &[BTreeMap<String, String>],
    target_key: &[String],
    nullable: bool,
) -> ReferenceEvidence {
    let keys: BTreeSet<Vec<&str>> = targets
        .iter()
        .filter_map(|row| tuple(row, target_key))
        .collect();
    let sampled = rows.len() as u32;
    let matched = rows
        .iter()
        .filter_map(|row| tuple(row, columns))
        .filter(|values| keys.contains(values))
        .count() as u32;
    let null_ratio_bp = if sampled == 0 {
        0
    } else {
        (u64::from(nulls(rows, columns)) * u64::from(PROFILE_RATIO_SCALE) / u64::from(sampled))
            as u16
    };
    ReferenceEvidence {
        sampled,
        matched,
        null_ratio_bp,
        nullable,
    }
}

/// Whether a column name suggests the key of a record kind: the key's own
/// name, or the record kind's name with or without the key (`account_id`,
/// `account`). Case and separators do not matter.
fn name_compatible(column: &str, record_kind: &str, key: &str) -> bool {
    let normalize = |text: &str| {
        text.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect::<String>()
    };
    let (column, kind, key) = (normalize(column), normalize(record_kind), normalize(key));
    let kind_stem = kind.trim_end_matches('s');
    column == key
        || [kind.as_str(), kind_stem]
            .iter()
            .any(|stem| column == *stem || column == format!("{stem}{key}"))
}

/// Name-only sensitivity hint for connectors that have no catalog marking.
/// A hint feeds review; it never assigns a marking.
pub fn column_name_suggests_sensitive(name: &str) -> bool {
    const HINTS: [&str; 10] = [
        "email", "phone", "ssn", "password", "secret", "token", "birth", "address", "iban", "tax",
    ];
    let lower = name.to_ascii_lowercase();
    HINTS.iter().any(|hint| lower.contains(hint))
}

fn validate_record_kind(kind: &DiscoveredRecordKind) -> Result<(), String> {
    require_token("record_kind", &kind.record_kind)?;
    require_token("schema_revision", &kind.schema_revision)?;
    if kind.columns.is_empty() || kind.columns.len() > MAX_DISCOVERED_COLUMNS {
        return Err("record kind must list between one and the maximum columns".into());
    }
    let mut names = BTreeSet::new();
    for column in &kind.columns {
        require_text("column name", &column.name)?;
        require_text("column type", &column.data_type)?;
        if !names.insert(column.name.as_str()) {
            return Err("column names must be unique within a record kind".into());
        }
        if let Some(profile) = column.profile
            && (profile.distinct_ratio_bp > PROFILE_RATIO_SCALE
                || profile.null_ratio_bp > PROFILE_RATIO_SCALE)
        {
            return Err("profile ratios must be within 0..=10000 basis points".into());
        }
    }
    if kind
        .value_findings
        .iter()
        .any(|finding| !names.contains(finding.column.as_str()))
    {
        return Err("value findings must name declared columns".into());
    }
    let mut candidates = BTreeSet::new();
    for candidate in &kind.key_candidates {
        let mut seen = BTreeSet::new();
        if candidate.is_empty()
            || !candidate
                .iter()
                .all(|column| names.contains(column.as_str()) && seen.insert(column.as_str()))
        {
            return Err("key candidates must name distinct declared columns".into());
        }
        if !candidates.insert(candidate) {
            return Err("key candidates must be unique".into());
        }
    }
    Ok(())
}

/// Registered-token shape (ADR 0060): no separators the identity format uses.
fn require_token(label: &str, value: &str) -> Result<(), String> {
    require_text(label, value)?;
    if value.contains([':', '#', '/']) {
        return Err(format!("{label} is not a canonical registered token"));
    }
    Ok(())
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || contains_secret_like_text(value)
    {
        return Err(format!("{label} is not bounded, trimmed, value-free text"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(name: &str) -> DiscoveredColumn {
        DiscoveredColumn {
            name: name.into(),
            data_type: "string".into(),
            nullable: false,
            profile: None,
        }
    }

    fn discovery(kinds: &[&str]) -> SourceDiscovery {
        SourceDiscovery {
            contract_version: SOURCE_DISCOVERY_VERSION.into(),
            source: "fake.crm".into(),
            record_kinds: kinds
                .iter()
                .map(|kind| DiscoveredRecordKind {
                    record_kind: (*kind).into(),
                    schema_revision: "v1".into(),
                    columns: vec![column("id"), column("region")],
                    key_candidates: vec![vec!["id".into()], vec!["region".into(), "id".into()]],
                    references: Vec::new(),
                    value_findings: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn drafts_follow_record_kinds() {
        let drafts = discovery(&["Account", "Contact"])
            .descriptor_drafts()
            .unwrap();
        assert_eq!(
            drafts
                .iter()
                .map(|draft| draft.record_kind.as_str())
                .collect::<Vec<_>>(),
            ["Account", "Contact"]
        );
        assert!(drafts.iter().all(|draft| draft.source == "fake.crm"));
    }

    #[test]
    fn rejects_unordered_kinds_unknown_keys_and_bad_ratios() {
        assert!(discovery(&["Contact", "Account"]).validate().is_err());
        assert!(discovery(&["Account", "Account"]).validate().is_err());

        let mut unknown_key = discovery(&["Account"]);
        unknown_key.record_kinds[0].key_candidates = vec![vec!["missing".into()]];
        assert!(unknown_key.validate().is_err());

        let mut repeated_key = discovery(&["Account"]);
        repeated_key.record_kinds[0].key_candidates = vec![vec!["id".into(), "id".into()]];
        assert!(repeated_key.validate().is_err());

        let mut ratio = discovery(&["Account"]);
        ratio.record_kinds[0].columns[0].profile = Some(ColumnProfileHint {
            distinct_ratio_bp: PROFILE_RATIO_SCALE + 1,
            null_ratio_bp: 0,
            possibly_sensitive: false,
        });
        assert!(ratio.validate().is_err());
    }

    #[test]
    fn rejects_identity_separators_and_secret_like_names() {
        let mut kind = discovery(&["Account"]);
        kind.record_kinds[0].record_kind = "crm:Account".into();
        assert!(kind.validate().is_err());

        let mut secret = discovery(&["Account"]);
        secret.record_kinds[0].columns[1].name = "github_pat_abc".into();
        assert!(secret.validate().is_err());
    }

    #[test]
    fn keyless_record_kind_is_valid() {
        let mut keyless = discovery(&["Event"]);
        keyless.record_kinds[0].key_candidates.clear();
        keyless.validate().unwrap();
    }

    struct SchemaOnly;

    impl SourceInspector for SchemaOnly {
        fn check(&mut self) -> Result<(), ConnectionFailure> {
            Ok(())
        }

        fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure> {
            Ok(discovery(&["Account"]))
        }
    }

    #[test]
    fn sample_defaults_to_unsupported_and_the_plane_caps_rows() {
        assert_eq!(
            SchemaOnly.sample_rows("Account").unwrap(),
            DiscoverySample::Unsupported
        );

        let extra = (0..=MAX_DISCOVERY_SAMPLE_ROWS)
            .map(|index| BTreeMap::from([("id".into(), index.to_string())]))
            .collect();
        let DiscoverySample::Rows { cells } =
            cap_discovery_sample(DiscoverySample::Rows { cells: extra })
        else {
            panic!("capped rows stay rows");
        };
        assert_eq!(cells.len(), MAX_DISCOVERY_SAMPLE_ROWS);
    }

    /// Declares `Contact.account_id`; the other links are left to inference.
    struct Crm {
        declares: bool,
        samples: bool,
    }

    fn rows(columns: &[&str], data: &[&[&str]]) -> Vec<BTreeMap<String, String>> {
        data.iter()
            .map(|row| {
                columns
                    .iter()
                    .zip(row.iter())
                    .map(|(column, value)| ((*column).into(), (*value).into()))
                    .collect()
            })
            .collect()
    }

    impl SourceInspector for Crm {
        fn check(&mut self) -> Result<(), ConnectionFailure> {
            Ok(())
        }

        fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure> {
            let kind = |name: &str, columns: &[(&str, bool)]| DiscoveredRecordKind {
                record_kind: name.into(),
                schema_revision: "v1".into(),
                columns: columns
                    .iter()
                    .map(|(name, nullable)| DiscoveredColumn {
                        nullable: *nullable,
                        ..column(name)
                    })
                    .collect(),
                key_candidates: vec![vec!["id".into()]],
                references: Vec::new(),
                value_findings: Vec::new(),
            };
            Ok(SourceDiscovery {
                contract_version: SOURCE_DISCOVERY_VERSION.into(),
                source: "fake.crm".into(),
                record_kinds: vec![
                    kind("Account", &[("id", false)]),
                    kind("Contact", &[("id", false), ("account_id", false)]),
                    kind("Invoice", &[("id", false), ("account_id", false)]),
                    kind(
                        "Order",
                        &[("id", false), ("account_id", false), ("contact_id", true)],
                    ),
                ],
            })
        }

        fn sample_rows(&mut self, record_kind: &str) -> Result<DiscoverySample, ConnectionFailure> {
            if !self.samples {
                return Ok(DiscoverySample::Unsupported);
            }
            let cells = match record_kind {
                "Account" => rows(&["id"], &[&["a1"], &["a2"], &["a3"]]),
                "Contact" => rows(&["id", "account_id"], &[&["c1", "a1"], &["c2", "a2"]]),
                // Shares a name with Account's key; the values are unrelated.
                "Invoice" => rows(&["id", "account_id"], &[&["i1", "x9"], &["i2", "x8"]]),
                "Order" => rows(
                    &["id", "account_id", "contact_id"],
                    &[
                        &["o1", "a1", "c1"],
                        &["o2", "a3", ""],
                        &["o3", "a1", "c2"],
                        &["o4", "a2", ""],
                    ],
                ),
                _ => return Ok(DiscoverySample::Unsupported),
            };
            Ok(DiscoverySample::Rows { cells })
        }

        fn declared_references(&mut self) -> Result<DeclaredReferences, ConnectionFailure> {
            Ok(if self.declares {
                DeclaredReferences::Declared(vec![DeclaredReference {
                    record_kind: "Contact".into(),
                    columns: vec!["account_id".into()],
                    target_record_kind: "Account".into(),
                    target_key: vec!["id".into()],
                }])
            } else {
                DeclaredReferences::Unsupported
            })
        }
    }

    fn attached(inspector: &mut Crm) -> (ReferenceSupport, Vec<(String, ReferenceCandidate)>) {
        let mut discovery = inspector.discover().unwrap();
        let support = attach_references(inspector, &mut discovery).unwrap();
        discovery.validate().unwrap();
        let all = discovery
            .record_kinds
            .into_iter()
            .flat_map(|kind| {
                kind.references
                    .into_iter()
                    .map(move |reference| (kind.record_kind.clone(), reference))
            })
            .collect();
        (support, all)
    }

    #[test]
    fn references_are_declared_or_inferred_with_counts_and_skip_look_alikes() {
        let (support, found) = attached(&mut Crm {
            declares: true,
            samples: true,
        });
        assert_eq!(support, ReferenceSupport::Attached);
        let summary: Vec<_> = found
            .iter()
            .map(|(kind, reference)| {
                let evidence = reference.evidence.unwrap();
                (
                    kind.as_str(),
                    reference.columns[0].as_str(),
                    reference.target_record_kind.as_str(),
                    reference.basis,
                    (
                        evidence.sampled,
                        evidence.matched,
                        evidence.null_ratio_bp,
                        evidence.nullable,
                    ),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "Contact",
                    "account_id",
                    "Account",
                    ReferenceBasis::Declared,
                    (2, 2, 0, false)
                ),
                (
                    "Order",
                    "account_id",
                    "Account",
                    ReferenceBasis::Inferred,
                    (4, 4, 0, false)
                ),
                (
                    "Order",
                    "contact_id",
                    "Contact",
                    ReferenceBasis::Inferred,
                    (4, 2, 5_000, true)
                ),
            ],
            "Invoice.account_id shares a name but no values, so it is not reported"
        );
        assert_eq!(
            attached(&mut Crm {
                declares: true,
                samples: true
            })
            .1,
            found
        );
    }

    #[test]
    fn references_need_a_declaration_or_a_sample_and_fail_closed_otherwise() {
        let (support, found) = attached(&mut Crm {
            declares: false,
            samples: false,
        });
        assert_eq!((support, found.len()), (ReferenceSupport::Unsupported, 0));

        // A declaration alone is reported, without evidence.
        let (_, found) = attached(&mut Crm {
            declares: true,
            samples: false,
        });
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.evidence, None);

        let mut discovery = Crm {
            declares: false,
            samples: true,
        }
        .discover()
        .unwrap();
        discovery.record_kinds[1]
            .references
            .push(ReferenceCandidate {
                columns: vec!["account_id".into()],
                target_record_kind: "Account".into(),
                target_key: vec!["name".into()],
                basis: ReferenceBasis::Declared,
                evidence: None,
            });
        assert!(discovery.validate().is_err());
    }

    /// One seeded instance of every shape, plus clean columns.
    struct Shapes {
        samples: bool,
    }

    impl SourceInspector for Shapes {
        fn check(&mut self) -> Result<(), ConnectionFailure> {
            Ok(())
        }

        fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure> {
            let typed = |name: &str, data_type: &str, nullable| DiscoveredColumn {
                data_type: data_type.into(),
                nullable,
                ..column(name)
            };
            let kind = |name: &str, columns: Vec<DiscoveredColumn>| DiscoveredRecordKind {
                record_kind: name.into(),
                schema_revision: "v1".into(),
                columns,
                key_candidates: vec![vec!["id".into()]],
                references: Vec::new(),
                value_findings: Vec::new(),
            };
            Ok(SourceDiscovery {
                contract_version: SOURCE_DISCOVERY_VERSION.into(),
                source: "fake.crm".into(),
                record_kinds: vec![
                    kind(
                        "Customer",
                        vec![
                            typed("id", "bigint", false),
                            typed("name", "text", false),
                            typed("signup", "text", false),
                            typed("created", "text", false),
                            typed("status", "text", false),
                            typed("amount", "text", false),
                            typed("quantity", "integer", false),
                            typed("region_id", "text", true),
                            typed("deleted_at", "timestamp", true),
                        ],
                    ),
                    kind("Region", vec![typed("id", "text", false)]),
                ],
            })
        }

        fn sample_rows(&mut self, record_kind: &str) -> Result<DiscoverySample, ConnectionFailure> {
            if !self.samples {
                return Ok(DiscoverySample::Unsupported);
            }
            let cells = match record_kind {
                "Customer" => rows(
                    &[
                        "id",
                        "name",
                        "signup",
                        "created",
                        "status",
                        "amount",
                        "quantity",
                        "region_id",
                        "deleted_at",
                    ],
                    &[
                        &[
                            "1",
                            "Ann",
                            "2024-03-01",
                            "2024-03-01",
                            "Active",
                            "12.5",
                            "3",
                            "r1",
                            "",
                        ],
                        &[
                            "2",
                            "Bob",
                            "01.03.2024",
                            "2024-03-02",
                            "active ",
                            "7",
                            "4",
                            "",
                            "",
                        ],
                        &[
                            "3",
                            "Cyd",
                            "2024-04-02",
                            "2024-03-03",
                            "ACTIVE",
                            "3",
                            "5",
                            "r2",
                            "2024-05-01",
                        ],
                        &[
                            "4",
                            "Dee",
                            "03.04.2024",
                            "2024-03-04",
                            "Closed",
                            "40",
                            "6",
                            "",
                            "",
                        ],
                    ],
                ),
                "Region" => rows(&["id"], &[&["r1"], &["r2"], &["r3"]]),
                _ => return Ok(DiscoverySample::Unsupported),
            };
            Ok(DiscoverySample::Rows { cells })
        }
    }

    #[test]
    fn value_findings_flag_each_shape_with_counts_and_no_values() {
        let mut source = Shapes { samples: true };
        let mut discovery = source.discover().unwrap();
        attach_references(&mut source, &mut discovery).unwrap();
        assert_eq!(
            attach_value_findings(&mut source, &mut discovery).unwrap(),
            ValueShapeSupport::Attached
        );
        discovery.validate().unwrap();
        let found: Vec<_> = discovery
            .record_kinds
            .iter()
            .flat_map(|kind| &kind.value_findings)
            .map(|finding| {
                (
                    finding.column.as_str(),
                    finding.code.as_str(),
                    finding.sampled,
                    finding.matched,
                    finding.formats.clone(),
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                ("amount", "numeric_as_text", 4, 4, vec![]),
                ("created", "temporal_as_text", 4, 4, vec!["iso_date"]),
                ("deleted_at", "soft_delete_candidate", 4, 3, vec![]),
                ("region_id", "nullable_reference", 4, 2, vec![]),
                (
                    "signup",
                    "mixed_temporal_format",
                    4,
                    4,
                    vec!["dotted_date", "iso_date"]
                ),
                ("status", "value_variants", 4, 4, vec![]),
            ],
            "name, quantity and the Region columns are clean"
        );
        let output = format!("{discovery:?}");
        for value in [
            "2024-03-01",
            "01.03.2024",
            "ACTIVE",
            "Closed",
            "12.5",
            "Ann",
            "r2",
        ] {
            assert!(!output.contains(value), "{value} leaked into the discovery");
        }
    }

    #[test]
    fn a_discovery_round_trips_through_the_v1_json_contract() {
        let mut source = Crm {
            declares: true,
            samples: true,
        };
        let mut discovery = source.discover().unwrap();
        attach_references(&mut source, &mut discovery).unwrap();
        attach_value_findings(&mut source, &mut discovery).unwrap();
        let json = serde_json::to_string(&discovery).unwrap();
        let loaded: SourceDiscovery = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded, discovery);
        assert!(json.contains("\"contract_version\":\"sekai.source-discovery/v1\""));
        assert!(json.contains("\"basis\":\"declared\""));
        assert!(json.contains("\"code\":\"nullable_reference\""));
    }

    #[test]
    fn value_findings_say_when_samples_are_unavailable() {
        let mut source = Shapes { samples: false };
        let mut discovery = source.discover().unwrap();
        assert_eq!(
            attach_value_findings(&mut source, &mut discovery).unwrap(),
            ValueShapeSupport::SamplesUnavailable
        );
        assert!(
            discovery
                .record_kinds
                .iter()
                .all(|kind| kind.value_findings.is_empty())
        );
    }
}
