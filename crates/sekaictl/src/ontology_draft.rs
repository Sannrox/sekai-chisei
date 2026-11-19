//! `sekaictl ontology draft` (#2296): a definition tree from a source discovery.
//!
//! The command reads a `sekai.source-discovery/v1` JSON file and writes the
//! existing ontology export layout. It never calls the plane to write. Member
//! ids and names are the discovery's record kinds and column names unchanged:
//! discovery already requires them to be canonical registered tokens.
//!
//! Inferred references become link types only at
//! [`sekai_source_sdk::MIN_INFERRED_REFERENCE_MATCH_BP`]; weaker candidates
//! are listed as dropped in `draft-report.json`. Columns flagged
//! `possibly_sensitive` take the namespace's most restrictive marking.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Map, Value};
use tonic::{Code, Request};

use crate::ontology_export::{ExportMember, LAYOUT_VERSION, Tree, build_tree, member_path, render};
use sekai_admin_client::client::connect_sekai;
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{ClassificationLattice as ProtoLattice, GetClassificationLatticeRequest};
use sekai_source_sdk::{
    MIN_INFERRED_REFERENCE_MATCH_BP, PROFILE_RATIO_SCALE, ReferenceBasis, ReferenceCandidate,
    ReferenceEvidence, SOURCE_DISCOVERY_VERSION, SourceDiscovery,
};
use sekai_types::classification_lattice::{ClassificationLattice, union_input_marking_tokens};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

const DRAFT_REPORT_VERSION: &str = "sekai.ontology-draft-report/v1";
const ORPHAN_REASON: &str = "drafted from source discovery; not yet consumed";
const REPORT_FILE: &str = "draft-report.json";
const DECISIONS_FILE: &str = "draft-decisions.json";

/// How many files a draft wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraftOutcome {
    pub files: usize,
}

/// Loads a discovery file, optionally the namespace lattice for sensitive
/// columns, and writes the tree.
pub async fn run(
    target: &str,
    discovery_path: &Path,
    out: &Path,
    namespace: Option<&str>,
    overwrite: bool,
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
    let tree = draft_tree(&discovery, marking.as_deref()).map_err(std::io::Error::other)?;
    write_tree(out, &tree, overwrite).map_err(std::io::Error::other)?;
    Ok(DraftOutcome { files: tree.len() })
}

/// Builds the canonical tree and report without touching the filesystem.
pub fn draft_tree(
    discovery: &SourceDiscovery,
    most_restrictive_marking: Option<&str>,
) -> Result<Tree, String> {
    discovery.validate()?;
    if discovery.contract_version != SOURCE_DISCOVERY_VERSION {
        return Err("unsupported source discovery contract".into());
    }
    if needs_marking(discovery) && most_restrictive_marking.is_none() {
        return Err(
            "possibly_sensitive columns need the namespace's most restrictive marking".into(),
        );
    }
    let mut object_reports = Vec::new();
    let mut members = Vec::new();
    for kind in &discovery.record_kinds {
        let (member, report) = object_type(discovery, kind, most_restrictive_marking);
        members.push(member);
        object_reports.push(report);
    }
    let (kept, dropped, link_members) = links(discovery);
    members.extend(link_members);

    let mut tree = build_tree(&members, None)?;
    let mut member_list = members
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
            "kept": kept,
        },
        "source": discovery.source,
    });
    tree.insert(REPORT_FILE.into(), render(&report)?);
    Ok(tree)
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
    kind: &sekai_source_sdk::DiscoveredRecordKind,
    marking: Option<&str>,
) -> (ExportMember, Value) {
    let properties: Vec<&str> = kind
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    let required: Vec<&str> = kind
        .columns
        .iter()
        .filter(|column| !column.nullable)
        .map(|column| column.name.as_str())
        .collect();
    let mut property_types = Map::new();
    for column in &kind.columns {
        property_types.insert(column.name.clone(), Value::String(column.data_type.clone()));
    }
    let mut property_markings = Map::new();
    if let Some(marking) = marking {
        for column in &kind.columns {
            if column
                .profile
                .is_some_and(|profile| profile.possibly_sensitive)
            {
                property_markings.insert(column.name.clone(), Value::String(marking.into()));
            }
        }
    }
    let key = kind.key_candidates.first().cloned().unwrap_or_default();
    let dropped_key_candidates: Vec<Vec<String>> =
        kind.key_candidates.iter().skip(1).cloned().collect();
    let mut body = serde_json::json!({
        "lint_suppressions": [{
            "reason": ORPHAN_REASON,
            "rule": "orphan_object_type",
        }],
        "name": kind.record_kind,
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
        "dropped_key_candidates": dropped_key_candidates,
        "findings": findings,
        "id": kind.record_kind,
        "key": key,
        "key_choice": if kind.key_candidates.is_empty() {
            "none"
        } else {
            "first_key_candidate"
        },
        "record_kind": kind.record_kind,
    });
    (
        ExportMember {
            kind: "object_type".into(),
            id: kind.record_kind.clone(),
            definition_json: body.to_string(),
        },
        report,
    )
}

fn links(discovery: &SourceDiscovery) -> (Vec<Value>, Vec<Value>, Vec<ExportMember>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    let mut members = Vec::new();
    for kind in &discovery.record_kinds {
        for reference in &kind.references {
            match classify_reference(kind, reference) {
                LinkDecision::Keep {
                    match_bp,
                    required,
                    cardinality,
                } => {
                    let id = link_id(&kind.record_kind, reference);
                    let body = serde_json::json!({
                        "cardinality": cardinality,
                        "columns": reference.columns,
                        "from": kind.record_kind,
                        "name": id,
                        "required": required,
                        "target_key": reference.target_key,
                        "to": reference.target_record_kind,
                    });
                    members.push(ExportMember {
                        kind: "link_type".into(),
                        id: id.clone(),
                        definition_json: body.to_string(),
                    });
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

fn link_id(from: &str, reference: &ReferenceCandidate) -> String {
    format!(
        "{from}_{}_{}",
        reference.columns.join("_"),
        reference.target_record_kind
    )
}

fn basis_name(basis: ReferenceBasis) -> &'static str {
    match basis {
        ReferenceBasis::Declared => "declared",
        ReferenceBasis::Inferred => "inferred",
        _ => "unknown",
    }
}

fn write_tree(out: &Path, tree: &Tree, overwrite: bool) -> Result<(), String> {
    let layout = out.join("layout.json");
    if layout.exists() {
        if !overwrite {
            return Err(format!(
                "{} already holds a definition tree; pass --overwrite to rewrite drafted members",
                out.display()
            ));
        }
        let allowed = previous_drafted_paths(out)?;
        for path in tree.keys() {
            let dest = out.join(path);
            if dest.exists() && !allowed.contains(path) {
                return Err(format!(
                    "{path}: exists and was not drafted before; refusing to overwrite"
                ));
            }
        }
        write_files(out, tree)
    } else {
        if out.exists() {
            for path in tree.keys() {
                if out.join(path).exists() {
                    return Err(format!(
                        "{} already holds {path}; pass --overwrite only for a previous draft",
                        out.display()
                    ));
                }
            }
        } else {
            std::fs::create_dir_all(out).map_err(|error| format!("{}: {error}", out.display()))?;
        }
        write_files(out, tree)
    }
}

fn previous_drafted_paths(out: &Path) -> Result<BTreeSet<String>, String> {
    let report_path = out.join(REPORT_FILE);
    let bytes = std::fs::read(&report_path).map_err(|error| {
        format!(
            "{}: {error}; --overwrite needs a previous {REPORT_FILE}",
            report_path.display()
        )
    })?;
    let report: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{}: {error}", report_path.display()))?;
    let mut allowed = BTreeSet::from([
        "layout.json".to_string(),
        REPORT_FILE.to_string(),
        DECISIONS_FILE.to_string(),
    ]);
    let Some(members) = report.get("members").and_then(Value::as_array) else {
        return Err(format!("{REPORT_FILE}: missing members list"));
    };
    for member in members {
        let Some(path) = member.get("path").and_then(Value::as_str) else {
            return Err(format!("{REPORT_FILE}: member is missing path"));
        };
        allowed.insert(path.to_string());
    }
    Ok(allowed)
}

fn write_files(out: &Path, tree: &Tree) -> Result<(), String> {
    for (path, body) in tree {
        let dest = out.join(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        let staging = dest.with_extension("json.partial");
        std::fs::write(&staging, body)
            .map_err(|error| format!("{}: {error}", staging.display()))?;
        std::fs::rename(&staging, &dest).map_err(|error| {
            let _ = std::fs::remove_file(&staging);
            format!("{}: {error}", dest.display())
        })?;
    }
    Ok(())
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
        let tree = draft_tree(&discovery, None).unwrap();
        let expected = fixture_dir().join("expected");
        let mut expected_files = BTreeMap::new();
        read_expected(&expected, &expected, &mut expected_files);
        assert_eq!(tree, expected_files, "checked-in tree");
        assert_eq!(
            tree,
            draft_tree(&crm(), None).unwrap(),
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
    fn overwrite_rewrites_only_previously_drafted_members() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tree");
        let tree = draft_tree(&crm(), None).unwrap();
        write_tree(&out, &tree, false).unwrap();
        write_tree(&out, &tree, false).unwrap_err();
        std::fs::write(out.join("object_type/Human.json"), "{}\n").unwrap();
        write_tree(&out, &tree, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("object_type/Human.json")).unwrap(),
            "{}\n",
            "stale and foreign members stay"
        );

        let mut extra = tree.clone();
        extra.insert(
            "object_type/Human.json".into(),
            "{\n  \"name\": \"Human\"\n}\n".into(),
        );
        let error = write_tree(&out, &extra, true).unwrap_err();
        assert!(error.contains("was not drafted before"), "{error}");
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
        let tree = draft_tree(&discovery, None).unwrap();
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
        let error = draft_tree(&discovery, None).unwrap_err();
        assert!(error.contains("possibly_sensitive"), "{error}");
        let marked = draft_tree(&discovery, Some("restricted")).unwrap();
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
