//! `sekaictl ontology draft` (#2296, #2297): a definition tree from a source
//! discovery, redrafted without losing review decisions.
//!
//! The command reads a `sekai.source-discovery/v1` JSON file and writes the
//! existing ontology export layout. It never calls the plane to write. Member
//! ids and names are the discovery's record kinds and column names unchanged
//! unless a decision renames them: discovery already requires them to be
//! canonical registered tokens.
//!
//! Inferred references become link types only at
//! [`sekai_source_sdk::MIN_INFERRED_REFERENCE_MATCH_BP`]; weaker candidates
//! are listed as dropped in `draft-report.json`. Columns flagged
//! `possibly_sensitive` take the namespace's most restrictive marking.
//!
//! Review decisions live in the tree as `draft-decisions.json` (see
//! [`Decision`]). A redraft (`--update`) honors them, rewrites only the members
//! the previous `draft-report.json` lists, removes owned members it no longer
//! drafts, and reports what the source gained or lost since that report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tonic::{Code, Request};

use crate::ontology_export::{ExportMember, LAYOUT_VERSION, Tree, build_tree, member_path, render};
use sekai_admin_client::client::connect_sekai;
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{ClassificationLattice as ProtoLattice, GetClassificationLatticeRequest};
use sekai_source_sdk::{
    DiscoveredRecordKind, MIN_INFERRED_REFERENCE_MATCH_BP, PROFILE_RATIO_SCALE, ReferenceBasis,
    ReferenceCandidate, ReferenceEvidence, SOURCE_DISCOVERY_VERSION, SourceDiscovery,
};
use sekai_types::classification_lattice::{ClassificationLattice, union_input_marking_tokens};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

const DRAFT_REPORT_VERSION: &str = "sekai.ontology-draft-report/v1";
const DECISIONS_VERSION: &str = "sekai.ontology-draft-decisions/v1";
const ORPHAN_REASON: &str = "drafted from source discovery; not yet consumed";
const REJECTED_WHY: &str = "rejected in draft-decisions.json";
const REPORT_FILE: &str = "draft-report.json";
const DECISIONS_FILE: &str = "draft-decisions.json";
const LAYOUT_FILE: &str = "layout.json";

/// What a draft wrote, removed, and noticed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftOutcome {
    pub files: usize,
    /// Members the previous draft owned that this draft no longer produces.
    pub removed: Vec<String>,
    /// Source changes since the previous `draft-report.json`; empty on a first draft.
    pub changes: Vec<SourceChange>,
    /// Decisions whose subject the source no longer has. They stay in the file.
    pub stale: Vec<Decision>,
}

/// One review decision in `draft-decisions.json`. Subjects name the source
/// (record kind, column, reference), never a member id, so renaming a member
/// does not orphan the other decisions about it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "DecisionLine", into = "DecisionLine")]
pub enum Decision {
    /// Never draft this record kind, column, or reference again.
    Reject(Target),
    /// Draft this member under `id` instead of the source-derived id.
    Rename { member: Member, id: String },
    /// The reviewer owns this member's file; a redraft never writes it.
    Keep(Member),
}

/// What a reject decision names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    Member(Member),
    Column { record_kind: String, column: String },
}

/// A drafted member by its source: an object type per record kind, a link
/// type per reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Member {
    ObjectType(String),
    LinkType(ReferenceKey),
}

/// A reference candidate's source identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReferenceKey {
    pub from: String,
    pub columns: Vec<String>,
    pub to: String,
}

/// The flat on-disk shape of a [`Decision`], one JSON object per line.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionLine {
    decision: Verb,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    column: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reference: Option<ReferenceKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Verb {
    Reject,
    Rename,
    Keep,
}

impl TryFrom<DecisionLine> for Decision {
    type Error = String;

    fn try_from(line: DecisionLine) -> Result<Self, String> {
        let target = match (line.record_kind, line.column, line.reference) {
            (Some(record_kind), None, None) => Target::Member(Member::ObjectType(record_kind)),
            (Some(record_kind), Some(column), None) => Target::Column {
                record_kind,
                column,
            },
            (None, None, Some(reference)) => Target::Member(Member::LinkType(reference)),
            _ => {
                return Err(
                    "a decision names record_kind (with an optional column) or reference".into(),
                );
            }
        };
        match (line.decision, target, line.id) {
            (Verb::Reject, target, None) => Ok(Decision::Reject(target)),
            (Verb::Keep, Target::Member(member), None) => Ok(Decision::Keep(member)),
            (Verb::Rename, Target::Member(member), Some(id)) => {
                if id.trim().is_empty() || id.trim() != id || id.contains([':', '#', '/']) {
                    return Err(format!(
                        "rename id {id:?} is not a canonical registered token"
                    ));
                }
                Ok(Decision::Rename { member, id })
            }
            (_, Target::Column { .. }, _) => Err("only reject can name a column".into()),
            (Verb::Rename, _, None) => Err("rename needs an id".into()),
            _ => Err("only rename takes an id".into()),
        }
    }
}

impl From<Decision> for DecisionLine {
    fn from(decision: Decision) -> Self {
        let (verb, target, id) = match decision {
            Decision::Reject(target) => (Verb::Reject, target, None),
            Decision::Rename { member, id } => (Verb::Rename, Target::Member(member), Some(id)),
            Decision::Keep(member) => (Verb::Keep, Target::Member(member), None),
        };
        let (record_kind, column, reference) = match target {
            Target::Member(Member::ObjectType(record_kind)) => (Some(record_kind), None, None),
            Target::Member(Member::LinkType(reference)) => (None, None, Some(reference)),
            Target::Column {
                record_kind,
                column,
            } => (Some(record_kind), Some(column), None),
        };
        DecisionLine {
            decision: verb,
            record_kind,
            column,
            reference,
            id,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        f.write_str(&line)
    }
}

/// A source change since the previous draft, keyed by source names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceChange {
    NewRecordKind(String),
    NewColumn {
        record_kind: String,
        column: String,
    },
    NewReference(ReferenceKey),
    VanishedReference(ReferenceKey),
    NewFinding {
        record_kind: String,
        column: String,
        code: String,
    },
}

impl fmt::Display for SourceChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reference =
            |key: &ReferenceKey| format!("{}({}) -> {}", key.from, key.columns.join(", "), key.to);
        match self {
            Self::NewRecordKind(kind) => write!(f, "new record kind {kind}"),
            Self::NewColumn {
                record_kind,
                column,
            } => write!(f, "new column {record_kind}.{column}"),
            Self::NewReference(key) => write!(f, "new reference candidate {}", reference(key)),
            Self::VanishedReference(key) => {
                write!(f, "vanished reference candidate {}", reference(key))
            }
            Self::NewFinding {
                record_kind,
                column,
                code,
            } => write!(f, "new finding {code} on {record_kind}.{column}"),
        }
    }
}

/// Loads a discovery file, optionally the namespace lattice for sensitive
/// columns, and writes the tree. `update` permits redrafting an existing draft.
pub async fn run(
    target: &str,
    discovery_path: &Path,
    out: &Path,
    namespace: Option<&str>,
    update: bool,
) -> Result<DraftOutcome, BoxErr> {
    let discovery = load_discovery(discovery_path).map_err(std::io::Error::other)?;
    let marking = if needs_marking(&discovery) {
        let namespace = namespace.ok_or_else(|| {
            std::io::Error::other(
                "--namespace is required when the discovery flags possibly_sensitive columns",
            )
        })?;
        Some(
            most_restrictive_marking(target, namespace)
                .await
                .map_err(std::io::Error::other)?,
        )
    } else {
        None
    };
    Ok(draft_into(out, &discovery, marking.as_deref(), update).map_err(std::io::Error::other)?)
}

/// Drafts into `out`, honoring the decisions already in it. Rerunning after an
/// interruption finishes the same draft: the report, which records ownership,
/// is written last.
pub fn draft_into(
    out: &Path,
    discovery: &SourceDiscovery,
    most_restrictive_marking: Option<&str>,
    update: bool,
) -> Result<DraftOutcome, String> {
    let decisions = load_decisions(out)?;
    let draft = draft_tree(discovery, most_restrictive_marking, &decisions)?;
    let (removed, changes) = write_draft(out, &draft, update)?;
    Ok(DraftOutcome {
        files: draft.tree.len(),
        removed,
        changes,
        stale: decisions
            .iter()
            .filter(|decision| !subject_exists(discovery, decision))
            .cloned()
            .collect(),
    })
}

/// A drafted tree plus the paths of members a keep decision withholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub tree: Tree,
    pub kept: BTreeSet<String>,
}

/// Builds the canonical tree and report without touching the filesystem.
pub fn draft_tree(
    discovery: &SourceDiscovery,
    most_restrictive_marking: Option<&str>,
    decisions: &[Decision],
) -> Result<Draft, String> {
    discovery.validate()?;
    if discovery.contract_version != SOURCE_DISCOVERY_VERSION {
        return Err("unsupported source discovery contract".into());
    }
    if needs_marking(discovery) && most_restrictive_marking.is_none() {
        return Err(
            "possibly_sensitive columns need the namespace's most restrictive marking".into(),
        );
    }
    let decided = Decisions(decisions);
    let mut object_reports = Vec::new();
    let mut members = Vec::new();
    for kind in &discovery.record_kinds {
        let (member, report) = object_type(discovery, kind, most_restrictive_marking, &decided);
        members.extend(member);
        object_reports.push(report);
    }
    let (kept_refs, dropped, link_members) = links(discovery, &decided);
    members.extend(link_members);

    let kept = decided.kept_paths();
    let mut owned = Vec::new();
    let mut folded = BTreeSet::new();
    for (_, export) in members {
        let path = member_path(&export.kind, &export.id);
        if !folded.insert(path.to_lowercase()) {
            return Err(format!(
                "{path}: two drafted members share this file; check the renames in {DECISIONS_FILE}"
            ));
        }
        if !kept.contains(&path) {
            owned.push(export);
        }
    }

    let mut tree = build_tree(&owned, None)?;
    let mut member_list = owned
        .iter()
        .map(|member| {
            serde_json::json!({
                "id": member.id,
                "kind": member.kind,
                "path": member_path(&member.kind, &member.id),
            })
        })
        .collect::<Vec<_>>();
    member_list.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let report = serde_json::json!({
        "contract_version": DRAFT_REPORT_VERSION,
        "inferred_link_confidence_bp": MIN_INFERRED_REFERENCE_MATCH_BP,
        "layout_version": LAYOUT_VERSION,
        "members": member_list,
        "object_types": object_reports,
        "references": {
            "dropped": dropped,
            "kept": kept_refs,
        },
        "source": discovery.source,
    });
    tree.insert(REPORT_FILE.into(), render(&report)?);
    if !decisions.is_empty() {
        tree.insert(DECISIONS_FILE.into(), render_decisions(decisions)?);
    }
    Ok(Draft { tree, kept })
}

/// Lookups over the decisions file. Linear scans: a file holds few decisions.
struct Decisions<'a>(&'a [Decision]);

impl Decisions<'_> {
    fn rejects(&self, target: &Target) -> bool {
        self.0
            .iter()
            .any(|decision| matches!(decision, Decision::Reject(rejected) if rejected == target))
    }

    fn rejects_kind(&self, record_kind: &str) -> bool {
        self.rejects(&Target::Member(Member::ObjectType(record_kind.into())))
    }

    fn rejects_column(&self, record_kind: &str, column: &str) -> bool {
        self.rejects(&Target::Column {
            record_kind: record_kind.into(),
            column: column.into(),
        })
    }

    fn renamed(&self, member: &Member) -> Option<&str> {
        self.0.iter().find_map(|decision| match decision {
            Decision::Rename {
                member: renamed,
                id,
            } if renamed == member => Some(id.as_str()),
            _ => None,
        })
    }

    fn type_id(&self, record_kind: &str) -> String {
        self.renamed(&Member::ObjectType(record_kind.into()))
            .unwrap_or(record_kind)
            .to_string()
    }

    fn member_path(&self, member: &Member) -> String {
        match member {
            Member::ObjectType(record_kind) => {
                member_path("object_type", &self.type_id(record_kind))
            }
            Member::LinkType(key) => member_path(
                "link_type",
                &self
                    .renamed(member)
                    .map_or_else(|| link_id(key), str::to_string),
            ),
        }
    }

    /// Files a keep decision protects, from the decisions alone, so a kept
    /// member survives even when its source subject vanished.
    fn kept_paths(&self) -> BTreeSet<String> {
        self.0
            .iter()
            .filter_map(|decision| match decision {
                Decision::Keep(member) => Some(self.member_path(member)),
                _ => None,
            })
            .collect()
    }
}

fn subject_exists(discovery: &SourceDiscovery, decision: &Decision) -> bool {
    let kind = |name: &str| {
        discovery
            .record_kinds
            .iter()
            .find(|kind| kind.record_kind == name)
    };
    let member = match decision {
        Decision::Reject(Target::Column {
            record_kind,
            column,
        }) => {
            return kind(record_kind)
                .is_some_and(|kind| kind.columns.iter().any(|known| &known.name == column));
        }
        Decision::Reject(Target::Member(member))
        | Decision::Rename { member, .. }
        | Decision::Keep(member) => member,
    };
    match member {
        Member::ObjectType(record_kind) => kind(record_kind).is_some(),
        Member::LinkType(key) => kind(&key.from).is_some_and(|kind| {
            kind.references
                .iter()
                .any(|reference| reference_key(kind, reference) == *key)
        }),
    }
}

/// Reads `draft-decisions.json` from `out`; none when it is absent. Rejects a
/// member decided two incompatible ways.
fn load_decisions(out: &Path) -> Result<Vec<Decision>, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DecisionsFile {
        contract_version: String,
        decisions: Vec<Decision>,
    }

    let path = out.join(DECISIONS_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let file: DecisionsFile =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    if file.contract_version != DECISIONS_VERSION {
        return Err(format!(
            "{}: unsupported contract {}",
            path.display(),
            file.contract_version
        ));
    }
    let decisions: Vec<Decision> = file
        .decisions
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut seen: BTreeMap<&Member, &Decision> = BTreeMap::new();
    for decision in &decisions {
        let member = match decision {
            Decision::Reject(Target::Column { .. }) => continue,
            Decision::Reject(Target::Member(member))
            | Decision::Rename { member, .. }
            | Decision::Keep(member) => member,
        };
        if let Some(other) = seen.insert(member, decision) {
            let compatible = matches!(
                (other, decision),
                (Decision::Rename { .. }, Decision::Keep(_))
                    | (Decision::Keep(_), Decision::Rename { .. })
            );
            if !compatible {
                return Err(format!(
                    "{DECISIONS_FILE}: conflicting decisions {other} and {decision}"
                ));
            }
        }
    }
    Ok(decisions)
}

/// One decision per line in sorted order, so two reviewers who add different
/// decisions touch different lines and their edits merge.
fn render_decisions(decisions: &[Decision]) -> Result<String, String> {
    let lines = decisions
        .iter()
        .map(|decision| {
            serde_json::to_string(decision)
                .map(|line| format!("    {line}"))
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!(
        "{{\n  \"contract_version\": \"{DECISIONS_VERSION}\",\n  \"decisions\": [\n{}\n  ]\n}}\n",
        lines.join(",\n")
    ))
}

fn load_discovery(path: &Path) -> Result<SourceDiscovery, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let discovery: SourceDiscovery =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    discovery.validate()?;
    Ok(discovery)
}

fn needs_marking(discovery: &SourceDiscovery) -> bool {
    discovery.record_kinds.iter().any(|kind| {
        kind.columns.iter().any(|column| {
            column
                .profile
                .is_some_and(|profile| profile.possibly_sensitive)
        })
    })
}

fn object_type(
    discovery: &SourceDiscovery,
    kind: &DiscoveredRecordKind,
    marking: Option<&str>,
    decided: &Decisions<'_>,
) -> (Option<(Member, ExportMember)>, Value) {
    let rejected = decided.rejects_kind(&kind.record_kind);
    let columns: Vec<_> = kind
        .columns
        .iter()
        .filter(|column| !decided.rejects_column(&kind.record_kind, &column.name))
        .collect();
    let properties: Vec<&str> = columns.iter().map(|column| column.name.as_str()).collect();
    let required: Vec<&str> = columns
        .iter()
        .filter(|column| !column.nullable)
        .map(|column| column.name.as_str())
        .collect();
    let mut property_types = Map::new();
    for column in &columns {
        property_types.insert(column.name.clone(), Value::String(column.data_type.clone()));
    }
    let mut property_markings = Map::new();
    if let Some(marking) = marking {
        for column in &columns {
            if column
                .profile
                .is_some_and(|profile| profile.possibly_sensitive)
            {
                property_markings.insert(column.name.clone(), Value::String(marking.into()));
            }
        }
    }
    let key = kind
        .key_candidates
        .iter()
        .find(|candidate| {
            candidate
                .iter()
                .all(|column| properties.contains(&column.as_str()))
        })
        .cloned()
        .unwrap_or_default();
    let dropped_key_candidates: Vec<&Vec<String>> = kind
        .key_candidates
        .iter()
        .filter(|candidate| **candidate != key)
        .collect();
    let id = decided.type_id(&kind.record_kind);
    let mut body = serde_json::json!({
        "lint_suppressions": [{
            "reason": ORPHAN_REASON,
            "rule": "orphan_object_type",
        }],
        "name": id,
        "properties": properties,
        "property_types": property_types,
        "required": required,
        "source": {
            "record_kind": kind.record_kind,
            "schema_revision": kind.schema_revision,
            "source": discovery.source,
        },
    });
    if !key.is_empty() {
        body["key"] = Value::Array(key.iter().cloned().map(Value::String).collect());
    }
    if !property_markings.is_empty() {
        body["property_markings"] = Value::Object(property_markings);
    }
    let findings: Vec<Value> = kind
        .value_findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "code": finding.code.as_str(),
                "column": finding.column,
                "formats": finding.formats,
                "matched": finding.matched,
                "sampled": finding.sampled,
            })
        })
        .collect();
    let report = serde_json::json!({
        "columns": kind.columns.iter().map(|column| column.name.as_str()).collect::<Vec<_>>(),
        "dropped_key_candidates": dropped_key_candidates,
        "findings": findings,
        "id": if rejected { Value::Null } else { Value::String(id.clone()) },
        "key": key,
        "key_choice": if key.is_empty() {
            "none"
        } else {
            "first_key_candidate"
        },
        "record_kind": kind.record_kind,
    });
    let member = (!rejected).then(|| {
        (
            Member::ObjectType(kind.record_kind.clone()),
            ExportMember {
                kind: "object_type".into(),
                id,
                definition_json: body.to_string(),
            },
        )
    });
    (member, report)
}

fn links(
    discovery: &SourceDiscovery,
    decided: &Decisions<'_>,
) -> (Vec<Value>, Vec<Value>, Vec<(Member, ExportMember)>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    let mut members = Vec::new();
    for kind in &discovery.record_kinds {
        for reference in &kind.references {
            let key = reference_key(kind, reference);
            let decision = if rejects_reference(decided, &key) {
                LinkDecision::Drop {
                    why: REJECTED_WHY.into(),
                    match_bp: reference.evidence.as_ref().map(match_bp),
                }
            } else {
                classify_reference(kind, reference)
            };
            match decision {
                LinkDecision::Keep {
                    match_bp,
                    required,
                    cardinality,
                } => {
                    let id = decided
                        .renamed(&Member::LinkType(key.clone()))
                        .map_or_else(|| link_id(&key), str::to_string);
                    let member = Member::LinkType(key);
                    let body = serde_json::json!({
                        "cardinality": cardinality,
                        "columns": reference.columns,
                        "from": decided.type_id(&kind.record_kind),
                        "name": id,
                        "required": required,
                        "target_key": reference.target_key,
                        "to": decided.type_id(&reference.target_record_kind),
                    });
                    members.push((
                        member,
                        ExportMember {
                            kind: "link_type".into(),
                            id: id.clone(),
                            definition_json: body.to_string(),
                        },
                    ));
                    kept.push(serde_json::json!({
                        "basis": basis_name(reference.basis),
                        "cardinality": cardinality,
                        "columns": reference.columns,
                        "from": kind.record_kind,
                        "link_id": id,
                        "match_bp": match_bp,
                        "required": required,
                        "target_key": reference.target_key,
                        "to": reference.target_record_kind,
                    }));
                }
                LinkDecision::Drop { why, match_bp } => {
                    dropped.push(serde_json::json!({
                        "basis": basis_name(reference.basis),
                        "columns": reference.columns,
                        "from": kind.record_kind,
                        "match_bp": match_bp,
                        "target_key": reference.target_key,
                        "to": reference.target_record_kind,
                        "why": why,
                    }));
                }
            }
        }
    }
    (kept, dropped, members)
}

/// A reference is rejected directly, through a rejected column, or through a
/// rejected record kind at either end.
fn rejects_reference(decided: &Decisions<'_>, key: &ReferenceKey) -> bool {
    decided.rejects(&Target::Member(Member::LinkType(key.clone())))
        || decided.rejects_kind(&key.from)
        || decided.rejects_kind(&key.to)
        || key
            .columns
            .iter()
            .any(|column| decided.rejects_column(&key.from, column))
}

fn reference_key(kind: &DiscoveredRecordKind, reference: &ReferenceCandidate) -> ReferenceKey {
    ReferenceKey {
        from: kind.record_kind.clone(),
        columns: reference.columns.clone(),
        to: reference.target_record_kind.clone(),
    }
}

enum LinkDecision {
    Keep {
        match_bp: Option<u16>,
        required: bool,
        cardinality: &'static str,
    },
    Drop {
        why: String,
        match_bp: Option<u16>,
    },
}

fn classify_reference(
    kind: &sekai_source_sdk::DiscoveredRecordKind,
    reference: &ReferenceCandidate,
) -> LinkDecision {
    let match_bp = reference.evidence.as_ref().map(match_bp);
    let required = !reference
        .evidence
        .map(|evidence| evidence.nullable)
        .unwrap_or_else(|| {
            kind.columns.iter().any(|column| {
                column.nullable && reference.columns.iter().any(|name| name == &column.name)
            })
        });
    let cardinality = if kind
        .key_candidates
        .iter()
        .any(|key| key == &reference.columns)
    {
        "one_to_one"
    } else {
        "many_to_one"
    };
    match reference.basis {
        ReferenceBasis::Declared => LinkDecision::Keep {
            match_bp,
            required,
            cardinality,
        },
        ReferenceBasis::Inferred => match match_bp {
            Some(bp) if bp >= MIN_INFERRED_REFERENCE_MATCH_BP => LinkDecision::Keep {
                match_bp: Some(bp),
                required,
                cardinality,
            },
            Some(bp) => LinkDecision::Drop {
                why: format!(
                    "inferred match {bp} is below {MIN_INFERRED_REFERENCE_MATCH_BP} basis points"
                ),
                match_bp: Some(bp),
            },
            None => LinkDecision::Drop {
                why: "inferred reference has no sample evidence".into(),
                match_bp: None,
            },
        },
        _ => LinkDecision::Drop {
            why: "unknown reference basis".into(),
            match_bp,
        },
    }
}

fn match_bp(evidence: &ReferenceEvidence) -> u16 {
    let present = present_rows(evidence);
    if present == 0 {
        0
    } else {
        ((u64::from(evidence.matched) * u64::from(PROFILE_RATIO_SCALE)) / u64::from(present))
            .min(u64::from(PROFILE_RATIO_SCALE)) as u16
    }
}

fn present_rows(evidence: &ReferenceEvidence) -> u32 {
    if evidence.sampled == 0 {
        return 0;
    }
    let nulls = (u64::from(evidence.null_ratio_bp) * u64::from(evidence.sampled))
        / u64::from(PROFILE_RATIO_SCALE);
    evidence.sampled.saturating_sub(nulls as u32)
}

fn link_id(key: &ReferenceKey) -> String {
    format!("{}_{}_{}", key.from, key.columns.join("_"), key.to)
}

fn basis_name(basis: ReferenceBasis) -> &'static str {
    match basis {
        ReferenceBasis::Declared => "declared",
        ReferenceBasis::Inferred => "inferred",
        _ => "unknown",
    }
}

/// The parts of a `draft-report.json` a redraft reads back: which members it
/// owns and what the source looked like.
#[derive(Deserialize)]
struct ReportSnapshot {
    members: Vec<ReportMember>,
    #[serde(default)]
    object_types: Vec<ReportKind>,
    #[serde(default)]
    references: ReportReferences,
}

#[derive(Deserialize)]
struct ReportMember {
    path: String,
}

#[derive(Deserialize)]
struct ReportKind {
    record_kind: String,
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    findings: Vec<ReportFinding>,
}

#[derive(Deserialize)]
struct ReportFinding {
    column: String,
    code: String,
}

#[derive(Default, Deserialize)]
struct ReportReferences {
    #[serde(default)]
    kept: Vec<ReferenceKey>,
    #[serde(default)]
    dropped: Vec<ReferenceKey>,
}

impl ReportSnapshot {
    /// Parses a report and refuses member paths outside `<kind>/<file>.json`,
    /// since a redraft deletes owned members by these paths.
    fn parse(label: &str, bytes: &[u8]) -> Result<Self, String> {
        let report: Self =
            serde_json::from_slice(bytes).map_err(|error| format!("{label}: {error}"))?;
        for member in &report.members {
            let components: Vec<_> = Path::new(&member.path).components().collect();
            let confined = matches!(
                components.as_slice(),
                [Component::Normal(_), Component::Normal(file)]
                    if Path::new(file).extension().is_some_and(|ext| ext == "json")
            );
            if !confined {
                return Err(format!(
                    "{label}: member path {:?} is not <kind>/<file>.json",
                    member.path
                ));
            }
        }
        Ok(report)
    }

    fn references(&self) -> BTreeSet<&ReferenceKey> {
        self.references
            .kept
            .iter()
            .chain(&self.references.dropped)
            .collect()
    }

    fn findings(&self) -> BTreeSet<(&str, &str, &str)> {
        self.object_types
            .iter()
            .flat_map(|kind| {
                kind.findings.iter().map(|finding| {
                    (
                        kind.record_kind.as_str(),
                        finding.column.as_str(),
                        finding.code.as_str(),
                    )
                })
            })
            .collect()
    }
}

/// What the source gained or lost between two reports, in a stable order.
fn source_changes(before: &ReportSnapshot, after: &ReportSnapshot) -> Vec<SourceChange> {
    let before_kinds: BTreeMap<&str, &ReportKind> = before
        .object_types
        .iter()
        .map(|kind| (kind.record_kind.as_str(), kind))
        .collect();
    let mut changes = BTreeSet::new();
    for kind in &after.object_types {
        let Some(previous) = before_kinds.get(kind.record_kind.as_str()) else {
            changes.insert(SourceChange::NewRecordKind(kind.record_kind.clone()));
            continue;
        };
        for column in &kind.columns {
            if !previous.columns.contains(column) {
                changes.insert(SourceChange::NewColumn {
                    record_kind: kind.record_kind.clone(),
                    column: column.clone(),
                });
            }
        }
    }
    let (old_refs, new_refs) = (before.references(), after.references());
    for key in new_refs.difference(&old_refs) {
        changes.insert(SourceChange::NewReference((*key).clone()));
    }
    for key in old_refs.difference(&new_refs) {
        changes.insert(SourceChange::VanishedReference((*key).clone()));
    }
    for (record_kind, column, code) in after.findings().difference(&before.findings()) {
        changes.insert(SourceChange::NewFinding {
            record_kind: (*record_kind).into(),
            column: (*column).into(),
            code: (*code).into(),
        });
    }
    changes.into_iter().collect()
}

/// Writes the draft. Over an existing tree (`update`), it rewrites only files
/// the previous report owns or whose content already matches, removes owned
/// members it no longer drafts unless kept, and writes the report last so an
/// interrupted run can be repeated.
fn write_draft(
    out: &Path,
    draft: &Draft,
    update: bool,
) -> Result<(Vec<String>, Vec<SourceChange>), String> {
    let previous = if out.join(LAYOUT_FILE).exists() {
        if !update {
            return Err(format!(
                "{} already holds a definition tree; pass --update to redraft it",
                out.display()
            ));
        }
        let report_path = out.join(REPORT_FILE);
        let bytes = std::fs::read(&report_path).map_err(|error| {
            format!(
                "{}: {error}; --update needs a previous {REPORT_FILE}",
                report_path.display()
            )
        })?;
        Some(ReportSnapshot::parse(REPORT_FILE, &bytes)?)
    } else {
        None
    };
    let owned: BTreeSet<&str> = previous
        .iter()
        .flat_map(|report| report.members.iter().map(|member| member.path.as_str()))
        .chain([LAYOUT_FILE, REPORT_FILE, DECISIONS_FILE])
        .collect();
    // Member directories must be real directories inside `out`: a symlinked
    // one would carry a write or a removal outside the tree.
    for path in owned
        .iter()
        .copied()
        .chain(draft.tree.keys().map(String::as_str))
    {
        if let Some(parent) = Path::new(path)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            let dir = out.join(parent);
            if std::fs::symlink_metadata(&dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
                return Err(format!(
                    "{}: is a symlink; refusing to draft through it",
                    dir.display()
                ));
            }
        }
    }
    for (path, body) in &draft.tree {
        if owned.contains(path.as_str()) {
            continue;
        }
        let dest = out.join(path);
        match std::fs::read_to_string(&dest) {
            Ok(existing) if existing == *body => {}
            Ok(_) if previous.is_some() => {
                return Err(format!(
                    "{path}: exists and was not drafted before; refusing to overwrite"
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "{} already holds {path}; pass --update only for a previous draft",
                    out.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", dest.display())),
        }
    }

    std::fs::create_dir_all(out).map_err(|error| format!("{}: {error}", out.display()))?;
    for (path, body) in &draft.tree {
        if path != REPORT_FILE {
            write_file(&out.join(path), body)?;
        }
    }
    let mut removed = Vec::new();
    for path in previous
        .iter()
        .flat_map(|report| report.members.iter().map(|member| &member.path))
    {
        if draft.tree.contains_key(path) || draft.kept.contains(path) {
            continue;
        }
        match std::fs::remove_file(out.join(path)) {
            Ok(()) => removed.push(path.clone()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{path}: {error}")),
        }
    }
    let report = &draft.tree[REPORT_FILE];
    write_file(&out.join(REPORT_FILE), report)?;
    let changes = match &previous {
        Some(before) => source_changes(
            before,
            &ReportSnapshot::parse(REPORT_FILE, report.as_bytes())?,
        ),
        None => Vec::new(),
    };
    Ok((removed, changes))
}

/// Replaces one file atomically through a sibling staging file.
fn write_file(dest: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let staging = dest.with_extension("json.partial");
    std::fs::write(&staging, body).map_err(|error| format!("{}: {error}", staging.display()))?;
    std::fs::rename(&staging, dest).map_err(|error| {
        let _ = std::fs::remove_file(&staging);
        format!("{}: {error}", dest.display())
    })
}

async fn most_restrictive_marking(target: &str, namespace: &str) -> Result<String, String> {
    let mut client = SekaiServiceClient::new(
        connect_sekai(target)
            .await
            .map_err(|error| error.to_string())?,
    );
    let lattice = match client
        .get_classification_lattice(Request::new(GetClassificationLatticeRequest {
            namespace: namespace.into(),
        }))
        .await
    {
        Ok(response) => response.into_inner().lattice,
        Err(status) if status.code() == Code::NotFound => None,
        Err(status) => return Err(status.to_string()),
    };
    let Some(lattice) = lattice else {
        return Err(format!(
            "namespace {namespace} has no classification lattice; cannot mark possibly_sensitive columns"
        ));
    };
    unique_most_restrictive(&lattice)
}

fn unique_most_restrictive(lattice: &ProtoLattice) -> Result<String, String> {
    let mut parents: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for edge in &lattice.parents {
        parents
            .entry(edge.child.clone())
            .or_default()
            .push(edge.parent.clone());
    }
    let prepared = ClassificationLattice {
        contract_version: lattice.contract_version.clone(),
        namespace: lattice.namespace.clone(),
        tokens: lattice.tokens.clone(),
        parents,
        incomparable: lattice
            .incomparable
            .iter()
            .map(|pair| (pair.left.clone(), pair.right.clone()))
            .collect(),
    }
    .prepare()?;
    let (_, joined) =
        union_input_marking_tokens(Some(&prepared), prepared.tokens.iter().map(Some))?;
    joined.ok_or_else(|| "namespace lattice has no unique most-restrictive marking".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_source_sdk::{
        ColumnProfileHint, DiscoveredColumn, DiscoveredRecordKind, ReferenceCandidate,
        ReferenceEvidence, ValueShapeCode, ValueShapeFinding,
    };

    fn column(name: &str, nullable: bool) -> DiscoveredColumn {
        DiscoveredColumn {
            name: name.into(),
            data_type: "string".into(),
            nullable,
            profile: None,
        }
    }

    fn crm() -> SourceDiscovery {
        let kind =
            |name: &str, columns: Vec<DiscoveredColumn>, references: Vec<ReferenceCandidate>| {
                DiscoveredRecordKind {
                    record_kind: name.into(),
                    schema_revision: "v1".into(),
                    columns,
                    key_candidates: vec![vec!["id".into()]],
                    references,
                    value_findings: Vec::new(),
                }
            };
        let evidence = |sampled, matched, null_ratio_bp, nullable| ReferenceEvidence {
            sampled,
            matched,
            null_ratio_bp,
            nullable,
        };
        let mut order = kind(
            "Order",
            vec![
                column("id", false),
                column("account_id", false),
                column("contact_id", true),
            ],
            vec![
                ReferenceCandidate {
                    columns: vec!["account_id".into()],
                    target_record_kind: "Account".into(),
                    target_key: vec!["id".into()],
                    basis: ReferenceBasis::Inferred,
                    evidence: Some(evidence(4, 4, 0, false)),
                },
                ReferenceCandidate {
                    columns: vec!["contact_id".into()],
                    target_record_kind: "Contact".into(),
                    target_key: vec!["id".into()],
                    basis: ReferenceBasis::Inferred,
                    evidence: Some(evidence(4, 2, 5_000, true)),
                },
            ],
        );
        order.value_findings = vec![ValueShapeFinding {
            column: "contact_id".into(),
            code: ValueShapeCode::NullableReference,
            sampled: 4,
            matched: 2,
            formats: Vec::new(),
        }];
        SourceDiscovery {
            contract_version: SOURCE_DISCOVERY_VERSION.into(),
            source: "fake.crm".into(),
            record_kinds: vec![
                kind("Account", vec![column("id", false)], Vec::new()),
                kind(
                    "Contact",
                    vec![column("id", false), column("account_id", false)],
                    vec![ReferenceCandidate {
                        columns: vec!["account_id".into()],
                        target_record_kind: "Account".into(),
                        target_key: vec!["id".into()],
                        basis: ReferenceBasis::Declared,
                        evidence: Some(evidence(2, 2, 0, false)),
                    }],
                ),
                kind(
                    "Invoice",
                    vec![column("id", false), column("account_id", false)],
                    Vec::new(),
                ),
                order,
            ],
        }
    }

    fn fixture_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ontology-draft")
    }

    #[test]
    fn the_crm_fixture_matches_the_checked_in_tree() {
        let discovery: SourceDiscovery =
            serde_json::from_slice(&std::fs::read(fixture_dir().join("discovery.json")).unwrap())
                .unwrap();
        assert_eq!(discovery, crm());
        let tree = draft_tree(&discovery, None, &[]).unwrap().tree;
        let expected = fixture_dir().join("expected");
        let mut expected_files = BTreeMap::new();
        read_expected(&expected, &expected, &mut expected_files);
        assert_eq!(tree, expected_files, "checked-in tree");
        assert_eq!(
            tree,
            draft_tree(&crm(), None, &[]).unwrap().tree,
            "drafting twice is byte-identical"
        );
    }

    fn read_expected(root: &Path, dir: &Path, files: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                read_expected(root, &path, files);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            files.insert(rel, std::fs::read_to_string(path).unwrap());
        }
    }

    #[test]
    fn update_rewrites_only_previously_drafted_members() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        draft_into(&out, &crm(), None, false).unwrap();
        let error = draft_into(&out, &crm(), None, false).unwrap_err();
        assert!(error.contains("--update"), "{error}");
        std::fs::write(out.join("object_type/Human.json"), "{}\n").unwrap();
        draft_into(&out, &crm(), None, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("object_type/Human.json")).unwrap(),
            "{}\n",
            "foreign members stay"
        );

        let mut human = crm();
        human.record_kinds.insert(
            2,
            DiscoveredRecordKind {
                record_kind: "Human".into(),
                schema_revision: "v1".into(),
                columns: vec![column("id", false)],
                key_candidates: Vec::new(),
                references: Vec::new(),
                value_findings: Vec::new(),
            },
        );
        let error = draft_into(&out, &human, None, true).unwrap_err();
        assert!(error.contains("was not drafted before"), "{error}");
    }

    fn read_tree(out: &Path) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        read_expected(out, out, &mut files);
        files
    }

    fn write_json(path: &Path, edit: impl FnOnce(&mut Value)) {
        let mut value: Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        edit(&mut value);
        std::fs::write(path, render(&value).unwrap()).unwrap();
    }

    const REJECT_ORDER_CONTACT: &str = r#"{"decision":"reject","reference":{"from":"Order","columns":["contact_id"],"to":"Contact"}}"#;
    const RENAME_ORDER: &str = r#"{"decision":"rename","record_kind":"Order","id":"SalesOrder"}"#;

    fn write_decisions(out: &Path, lines: &[&str]) {
        std::fs::write(
            out.join(DECISIONS_FILE),
            format!(
                "{{\"contract_version\":\"{DECISIONS_VERSION}\",\"decisions\":[{}]}}",
                lines.join(",")
            ),
        )
        .unwrap();
    }

    /// A first draft a reviewer edited by hand: the coincidental Order to
    /// Contact link deleted and Order renamed to SalesOrder, both recorded.
    fn reviewed_draft(out: &Path) {
        draft_into(out, &crm(), None, false).unwrap();
        std::fs::remove_file(out.join("link_type/Order_contact_id_Contact.json")).unwrap();
        std::fs::rename(
            out.join("object_type/Order.json"),
            out.join("object_type/SalesOrder.json"),
        )
        .unwrap();
        write_json(&out.join("object_type/SalesOrder.json"), |order| {
            order["name"] = "SalesOrder".into();
        });
        write_json(
            &out.join("link_type/Order_account_id_Account.json"),
            |link| {
                link["from"] = "SalesOrder".into();
            },
        );
        write_decisions(out, &[RENAME_ORDER, REJECT_ORDER_CONTACT]);
    }

    #[test]
    fn a_redraft_of_unchanged_data_keeps_a_reviewed_tree() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        reviewed_draft(&out);
        let mut reviewed = read_tree(&out);

        let outcome = draft_into(&out, &crm(), None, true).unwrap();
        assert!(outcome.changes.is_empty(), "{:?}", outcome.changes);
        assert!(outcome.stale.is_empty(), "{:?}", outcome.stale);
        assert!(
            outcome.removed.is_empty(),
            "the reviewer already moved Order: {:?}",
            outcome.removed
        );
        let mut redrafted = read_tree(&out);
        for side in [&mut reviewed, &mut redrafted] {
            side.remove(REPORT_FILE);
            side.remove(DECISIONS_FILE);
        }
        assert_eq!(redrafted, reviewed);

        let settled = read_tree(&out);
        draft_into(&out, &crm(), None, true).unwrap();
        assert_eq!(
            read_tree(&out),
            settled,
            "a second redraft is byte-identical"
        );
    }

    #[test]
    fn a_redraft_adds_only_the_new_column_and_type_and_reports_them() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        reviewed_draft(&out);
        draft_into(&out, &crm(), None, true).unwrap();
        let before = read_tree(&out);

        let mut grown = crm();
        grown.record_kinds[0].columns.push(column("region", true));
        grown.record_kinds.push(DiscoveredRecordKind {
            record_kind: "Ticket".into(),
            schema_revision: "v1".into(),
            columns: vec![column("id", false)],
            key_candidates: vec![vec!["id".into()]],
            references: Vec::new(),
            value_findings: Vec::new(),
        });
        let outcome = draft_into(&out, &grown, None, true).unwrap();
        assert_eq!(
            outcome.changes,
            vec![
                SourceChange::NewRecordKind("Ticket".into()),
                SourceChange::NewColumn {
                    record_kind: "Account".into(),
                    column: "region".into(),
                },
            ]
        );
        let after = read_tree(&out);
        let changed: Vec<&str> = after
            .iter()
            .filter(|(path, body)| before.get(*path) != Some(body))
            .map(|(path, _)| path.as_str())
            .collect();
        assert_eq!(
            changed,
            [
                REPORT_FILE,
                "object_type/Account.json",
                "object_type/Ticket.json"
            ]
        );
        assert!(!after.contains_key("link_type/Order_contact_id_Contact.json"));
        assert!(!after.contains_key("object_type/Order.json"));
    }

    #[test]
    fn a_decision_about_a_vanished_subject_is_reported_stale_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        draft_into(&out, &crm(), None, false).unwrap();
        let gone = r#"{"decision":"reject","record_kind":"Order","column":"discount"}"#;
        write_decisions(&out, &[gone, RENAME_ORDER]);

        let outcome = draft_into(&out, &crm(), None, true).unwrap();
        assert_eq!(outcome.stale.len(), 1);
        assert_eq!(outcome.stale[0].to_string(), gone);
        assert_eq!(
            outcome.removed,
            ["object_type/Order.json"],
            "the owned old name goes"
        );
        assert!(
            std::fs::read_to_string(out.join(DECISIONS_FILE))
                .unwrap()
                .contains(gone)
        );
    }

    #[test]
    fn an_interrupted_rename_finishes_on_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        draft_into(&out, &crm(), None, false).unwrap();
        let first_report = std::fs::read_to_string(out.join(REPORT_FILE)).unwrap();
        let order = std::fs::read_to_string(out.join("object_type/Order.json")).unwrap();
        write_decisions(&out, &[RENAME_ORDER]);
        draft_into(&out, &crm(), None, true).unwrap();
        let finished = read_tree(&out);

        // Crash before the old file was removed and the report written.
        std::fs::write(out.join(REPORT_FILE), first_report).unwrap();
        std::fs::write(out.join("object_type/Order.json"), order).unwrap();
        let outcome = draft_into(&out, &crm(), None, true).unwrap();
        assert_eq!(outcome.removed, ["object_type/Order.json"]);
        assert_eq!(read_tree(&out), finished);
    }

    #[test]
    fn a_kept_member_is_never_written_even_after_its_source_vanishes() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        draft_into(&out, &crm(), None, false).unwrap();
        let edited = "{\"name\":\"Invoice\"}\n";
        std::fs::write(out.join("object_type/Invoice.json"), edited).unwrap();
        write_decisions(&out, &[r#"{"decision":"keep","record_kind":"Invoice"}"#]);
        draft_into(&out, &crm(), None, true).unwrap();
        let mut without_invoice = crm();
        without_invoice.record_kinds.remove(2);
        let outcome = draft_into(&out, &without_invoice, None, true).unwrap();
        assert!(outcome.removed.is_empty(), "{:?}", outcome.removed);
        assert_eq!(
            std::fs::read_to_string(out.join("object_type/Invoice.json")).unwrap(),
            edited
        );
    }

    #[test]
    fn a_report_naming_a_path_outside_the_tree_is_refused_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        draft_into(&out, &crm(), None, false).unwrap();
        let victim = dir.path().join("victim.json");
        std::fs::write(&victim, "{}").unwrap();
        write_json(&out.join(REPORT_FILE), |report| {
            report["members"][0]["path"] = "../victim.json".into();
        });
        let error = draft_into(&out, &crm(), None, true).unwrap_err();
        assert!(error.contains("is not <kind>/<file>.json"), "{error}");
        assert!(victim.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_member_directory_is_refused_before_any_removal() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        draft_into(&out, &crm(), None, false).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("Invoice.json"), "{}").unwrap();
        std::fs::remove_dir_all(out.join("object_type")).unwrap();
        std::os::unix::fs::symlink(&outside, out.join("object_type")).unwrap();
        let mut without_invoice = crm();
        without_invoice.record_kinds.remove(2);
        let error = draft_into(&out, &without_invoice, None, true).unwrap_err();
        assert!(error.contains("is a symlink"), "{error}");
        assert!(outside.join("Invoice.json").exists());
    }

    #[test]
    fn two_reviewers_adding_different_decisions_merge_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let render = |lines: &[&str]| {
            let decisions = lines
                .iter()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect::<BTreeSet<Decision>>()
                .into_iter()
                .collect::<Vec<_>>();
            render_decisions(&decisions).unwrap()
        };
        let keep = |kind: &str| format!(r#"{{"decision":"keep","record_kind":"{kind}"}}"#);
        let (a, c, e, g) = (keep("A"), keep("C"), keep("E"), keep("G"));
        let (b, f) = (keep("B"), keep("F"));
        let base = render(&[&a, &c, &e, &g]);
        let ours = render(&[&a, &b, &c, &e, &g]);
        let theirs = render(&[&a, &c, &e, &f, &g]);
        for (name, body) in [("base", &base), ("ours", &ours), ("theirs", &theirs)] {
            std::fs::write(dir.path().join(name), body).unwrap();
        }
        let merged = std::process::Command::new("git")
            .args(["merge-file", "-p", "ours", "base", "theirs"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(merged.status.success(), "conflict: {merged:?}");
        assert_eq!(
            String::from_utf8(merged.stdout).unwrap(),
            render(&[&a, &b, &c, &e, &f, &g])
        );
    }

    #[test]
    fn a_rejected_column_leaves_the_type_and_takes_its_links() {
        let decisions = [Decision::Reject(Target::Column {
            record_kind: "Order".into(),
            column: "account_id".into(),
        })];
        let tree = draft_tree(&crm(), None, &decisions).unwrap().tree;
        let order: Value = serde_json::from_str(&tree["object_type/Order.json"]).unwrap();
        assert_eq!(order["properties"], serde_json::json!(["id", "contact_id"]));
        assert!(!tree.contains_key("link_type/Order_account_id_Account.json"));
        let report: Value = serde_json::from_str(&tree[REPORT_FILE]).unwrap();
        assert_eq!(report["references"]["dropped"][0]["why"], REJECTED_WHY);
    }

    #[test]
    fn a_member_rejected_and_renamed_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write_decisions(
            dir.path(),
            &[
                RENAME_ORDER,
                r#"{"decision":"reject","record_kind":"Order"}"#,
            ],
        );
        let error = load_decisions(dir.path()).unwrap_err();
        assert!(error.contains("conflicting decisions"), "{error}");
    }

    #[test]
    fn a_weak_inferred_reference_is_dropped_and_sensitive_columns_need_a_marking() {
        let mut discovery = crm();
        discovery.record_kinds[3].references[0].evidence = Some(ReferenceEvidence {
            sampled: 4,
            matched: 1,
            null_ratio_bp: 0,
            nullable: false,
        });
        let tree = draft_tree(&discovery, None, &[]).unwrap().tree;
        let report: Value = serde_json::from_str(&tree[REPORT_FILE]).unwrap();
        assert!(
            report["references"]["dropped"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["from"] == "Order" && item["to"] == "Account"),
            "{report}"
        );
        assert!(!tree.contains_key("link_type/Order_account_id_Account.json"));

        discovery.record_kinds[0].columns[0].profile = Some(ColumnProfileHint {
            distinct_ratio_bp: 10_000,
            null_ratio_bp: 0,
            possibly_sensitive: true,
        });
        let error = draft_tree(&discovery, None, &[]).unwrap_err();
        assert!(error.contains("possibly_sensitive"), "{error}");
        let marked = draft_tree(&discovery, Some("restricted"), &[])
            .unwrap()
            .tree;
        let account: Value = serde_json::from_str(&marked["object_type/Account.json"]).unwrap();
        assert_eq!(account["property_markings"]["id"], "restricted");
    }

    #[test]
    fn the_default_lattice_folds_to_restricted() {
        let domain = ClassificationLattice::default_evidence_lattice("ns");
        let proto = ProtoLattice {
            contract_version: domain.contract_version.clone(),
            namespace: domain.namespace.clone(),
            tokens: domain.tokens.clone(),
            parents: domain
                .parents
                .iter()
                .flat_map(|(child, parents)| {
                    parents
                        .iter()
                        .map(move |parent| sekai_proto::sekai::ClassificationParentEdge {
                            child: child.clone(),
                            parent: parent.clone(),
                        })
                })
                .collect(),
            incomparable: Vec::new(),
            digest: String::new(),
        };
        assert_eq!(unique_most_restrictive(&proto).unwrap(), "restricted");
    }
}
