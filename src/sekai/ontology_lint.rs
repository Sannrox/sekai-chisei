//! Ontology lint (#1454): structural findings over one namespace.
//!
//! The rules read a namespace's published definition and what the caller
//! may see of its data. They find:
//! - object types with no visible link between their objects and others and
//!   no visible consumer binding;
//! - objects with no link to another object the caller can see;
//! - object and link types without an owner;
//! - markings applied to almost every visible object, or that almost every
//!   visible principal profile is cleared for;
//! - enabled Action types with no instance the caller may see.
//!
//! The caller gathers the inputs already filtered by its read policy, so a
//! finding never names what the caller cannot see. Rules are pure over the
//! inputs and findings are sorted, so one input always lints the same.

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::Object;
use crate::sekai::definition_branch::DefinitionMember;
use crate::sekai::markings::{object_marking_token, parse_optional_classification};
use sekai_types::evidence_vocabulary::EvidenceClassification;

pub const RULE_ORPHAN_OBJECT_TYPE: &str = "orphan_object_type";
pub const RULE_ORPHAN_OBJECT: &str = "orphan_object";
pub const RULE_UNOWNED_OBJECT_TYPE: &str = "unowned_object_type";
pub const RULE_UNOWNED_LINK_TYPE: &str = "unowned_link_type";
pub const RULE_BROAD_MARKING_APPLIED: &str = "broad_marking_applied";
pub const RULE_BROAD_MARKING_GRANTED: &str = "broad_marking_granted";
pub const RULE_ACTION_TYPE_NEVER_RUN: &str = "action_type_never_run";

pub const SEVERITY_WARNING: &str = "warning";
pub const SEVERITY_INFO: &str = "info";

/// A marking is broad when it covers at least this share (in percent) of a
/// population of at least [`BROAD_MIN_POPULATION`].
pub const BROAD_SHARE_PERCENT: usize = 90;
pub const BROAD_MIN_POPULATION: usize = 10;
/// Findings past this many are dropped and the report is partial.
pub const MAX_FINDINGS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LintFinding {
    pub rule: &'static str,
    pub subject_kind: &'static str,
    pub subject_id: String,
    pub severity: &'static str,
    pub detail: String,
}

/// What the caller may see of one namespace.
#[derive(Debug, Default)]
pub struct LintInput {
    /// Members of the published definition revision.
    pub members: Vec<DefinitionMember>,
    /// Objects of the namespace the caller may read.
    pub objects: Vec<Object>,
    /// Whether `objects` is every object the caller may read there. The
    /// object rules run only on a complete scan.
    pub objects_complete: bool,
    /// Ids in `objects` with a link to or from another object the caller
    /// may see in the namespace.
    pub linked: BTreeSet<String>,
    /// `(member_kind, member_id)` referenced by a visible consumer binding.
    pub consumed: BTreeSet<(String, String)>,
    /// Object types whose visible catalog entry lists an owner.
    pub catalog_owned: BTreeSet<String>,
    /// Enabled Action type ids the caller administers, each with whether an
    /// instance the caller may see exists.
    pub action_types: BTreeMap<String, bool>,
    /// Classification ceilings of the principal profiles the caller may
    /// read; `None` for a profile with no ceiling.
    pub clearances: Vec<Option<EvidenceClassification>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LintReport {
    pub findings: Vec<LintFinding>,
    /// False when the object scan was cut short or findings were dropped.
    pub complete: bool,
}

fn finding(
    rule: &'static str,
    subject_kind: &'static str,
    subject_id: &str,
    severity: &'static str,
    detail: String,
) -> LintFinding {
    LintFinding {
        rule,
        subject_kind,
        subject_id: subject_id.into(),
        severity,
        detail,
    }
}

/// A definition declares its owner as a non-empty `owner` string.
fn declares_owner(member: &DefinitionMember) -> bool {
    serde_json::from_str::<serde_json::Value>(&member.definition_json)
        .ok()
        .and_then(|value| {
            value
                .get("owner")
                .and_then(serde_json::Value::as_str)
                .map(|owner| !owner.trim().is_empty())
        })
        .unwrap_or(false)
}

fn broad(count: usize, population: usize) -> bool {
    population >= BROAD_MIN_POPULATION && count * 100 >= population * BROAD_SHARE_PERCENT
}

pub fn lint(input: &LintInput) -> LintReport {
    let mut findings = Vec::new();
    let of_kind = |kind: &'static str| {
        input
            .members
            .iter()
            .filter(move |member| member.member_kind == kind)
    };
    // Types with a linked object; only known on a complete object scan.
    let linked_types: BTreeSet<&str> = input
        .objects
        .iter()
        .filter(|object| input.linked.contains(&object.id))
        .map(|object| object.kind.as_str())
        .collect();
    for object_type in of_kind("object_type") {
        let id = &object_type.member_id;
        if input.objects_complete
            && !linked_types.contains(id.as_str())
            && !input
                .consumed
                .contains(&("object_type".to_string(), id.clone()))
        {
            findings.push(finding(
                RULE_ORPHAN_OBJECT_TYPE,
                "object_type",
                id,
                SEVERITY_WARNING,
                "no visible object of this type is linked, and no consumer references it".into(),
            ));
        }
        if !declares_owner(object_type) && !input.catalog_owned.contains(id) {
            findings.push(finding(
                RULE_UNOWNED_OBJECT_TYPE,
                "object_type",
                id,
                SEVERITY_WARNING,
                "neither the definition nor its catalog entry names an owner".into(),
            ));
        }
    }
    for link_type in of_kind("link_type") {
        if !declares_owner(link_type) {
            findings.push(finding(
                RULE_UNOWNED_LINK_TYPE,
                "link_type",
                &link_type.member_id,
                SEVERITY_WARNING,
                "the definition names no owner".into(),
            ));
        }
    }
    if input.objects_complete {
        for object in &input.objects {
            if !input.linked.contains(&object.id) {
                findings.push(finding(
                    RULE_ORPHAN_OBJECT,
                    "object",
                    &object.id,
                    SEVERITY_INFO,
                    "no link to another visible object".into(),
                ));
            }
        }
        let mut applied: BTreeMap<&str, usize> = BTreeMap::new();
        for token in input.objects.iter().filter_map(object_marking_token) {
            *applied.entry(token).or_default() += 1;
        }
        for (token, count) in applied {
            if broad(count, input.objects.len()) {
                findings.push(finding(
                    RULE_BROAD_MARKING_APPLIED,
                    "marking",
                    token,
                    SEVERITY_WARNING,
                    format!(
                        "applied to {count} of {} visible objects",
                        input.objects.len()
                    ),
                ));
            }
        }
    }
    // A ceiling clears its own level and every level below it.
    for level in [
        EvidenceClassification::Internal,
        EvidenceClassification::Confidential,
        EvidenceClassification::Restricted,
    ] {
        let cleared = input
            .clearances
            .iter()
            .filter(|ceiling| ceiling.is_some_and(|ceiling| ceiling >= level))
            .count();
        if broad(cleared, input.clearances.len()) {
            findings.push(finding(
                RULE_BROAD_MARKING_GRANTED,
                "marking",
                level.as_str(),
                SEVERITY_WARNING,
                format!(
                    "{cleared} of {} visible principal profiles are cleared for it",
                    input.clearances.len()
                ),
            ));
        }
    }
    for (type_id, ran) in &input.action_types {
        if !ran {
            findings.push(finding(
                RULE_ACTION_TYPE_NEVER_RUN,
                "action_type",
                type_id,
                SEVERITY_INFO,
                "no instance of this Action type exists".into(),
            ));
        }
    }
    findings.sort();
    let complete = input.objects_complete && findings.len() <= MAX_FINDINGS;
    findings.truncate(MAX_FINDINGS);
    LintReport { findings, complete }
}

/// The ceiling a principal profile clears, when it names a standard level.
pub fn profile_clearance(profile: &Object) -> Option<EvidenceClassification> {
    profile
        .properties
        .get(crate::sekai::markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY)
        .and_then(|raw| parse_optional_classification(raw).ok().flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn member(kind: &str, id: &str, json: &str) -> DefinitionMember {
        DefinitionMember {
            contract_version: String::new(),
            namespace: "acme".into(),
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
    }

    /// An object whose kind follows its id: `u-*` users, else tickets.
    fn object(id: &str, marking: &str) -> Object {
        Object {
            id: id.into(),
            kind: if id.starts_with("u-") {
                "User"
            } else {
                "Ticket"
            }
            .into(),
            name: id.into(),
            namespace: "acme".into(),
            properties: if marking.is_empty() {
                HashMap::new()
            } else {
                HashMap::from([("access_marking".into(), marking.into())])
            },
            external_id: String::new(),
            created: 0,
            updated: 0,
        }
    }

    /// Owned, linked, consumed and run: nothing to report.
    fn clean() -> LintInput {
        LintInput {
            members: vec![
                member("object_type", "Ticket", r#"{"owner":"support"}"#),
                member("object_type", "User", r#"{"owner":"identity"}"#),
                member("link_type", "AssignedTo", r#"{"owner":"support"}"#),
            ],
            objects: vec![object("t-1", "internal"), object("u-1", "")],
            objects_complete: true,
            linked: ["t-1", "u-1"].map(String::from).into(),
            action_types: BTreeMap::from([("ticket.close".into(), true)]),
            clearances: vec![Some(EvidenceClassification::Internal), None],
            ..LintInput::default()
        }
    }

    #[test]
    fn a_clean_namespace_has_no_findings() {
        assert_eq!(
            lint(&clean()),
            LintReport {
                findings: Vec::new(),
                complete: true
            }
        );
    }

    #[test]
    fn one_of_each_problem_gives_exactly_those_findings() {
        let mut input = clean();
        // Unowned, referenced only by a consumer: one finding (unowned).
        input
            .members
            .push(member("object_type", "Invoice", r#"{"name":"Invoice"}"#));
        input
            .consumed
            .insert(("object_type".into(), "Invoice".into()));
        // Owned through the catalog, referenced by nothing: orphan.
        input.members.push(member("object_type", "Note", "{}"));
        input.catalog_owned.insert("Note".into());
        input.members.push(member("link_type", "Mentions", "{}"));
        input.objects.push(object("t-2", ""));
        input.action_types.insert("ticket.reopen".into(), false);
        let report = lint(&input);
        let ids: Vec<(&str, &str)> = report
            .findings
            .iter()
            .map(|finding| (finding.rule, finding.subject_id.as_str()))
            .collect();
        assert_eq!(
            ids,
            [
                (RULE_ACTION_TYPE_NEVER_RUN, "ticket.reopen"),
                (RULE_ORPHAN_OBJECT, "t-2"),
                (RULE_ORPHAN_OBJECT_TYPE, "Note"),
                (RULE_UNOWNED_LINK_TYPE, "Mentions"),
                (RULE_UNOWNED_OBJECT_TYPE, "Invoice"),
            ]
        );
    }

    #[test]
    fn a_marking_on_or_cleared_for_almost_everything_is_broad() {
        let mut input = clean();
        // One user, then tickets, all linked and marked.
        input.objects = std::iter::once("u-1".to_string())
            .chain((0..9).map(|n| format!("o-{n}")))
            .map(|id| object(&id, "internal"))
            .collect();
        input.linked = input.objects.iter().map(|o| o.id.clone()).collect();
        input.clearances = vec![Some(EvidenceClassification::Confidential); 9];
        input.clearances.push(None);
        let report = lint(&input);
        let broad: Vec<(&str, &str)> = report
            .findings
            .iter()
            .map(|finding| (finding.rule, finding.subject_id.as_str()))
            .collect();
        assert_eq!(
            broad,
            [
                (RULE_BROAD_MARKING_APPLIED, "internal"),
                (RULE_BROAD_MARKING_GRANTED, "confidential"),
                (RULE_BROAD_MARKING_GRANTED, "internal"),
            ]
        );
        // Below the minimum population nothing is broad.
        input.objects.truncate(9);
        input.clearances.truncate(9);
        assert!(lint(&input).findings.is_empty());
    }

    #[test]
    fn a_partial_scan_skips_the_object_rules() {
        let mut input = clean();
        input.objects.push(object("t-2", ""));
        input.objects_complete = false;
        assert_eq!(
            lint(&input),
            LintReport {
                findings: Vec::new(),
                complete: false
            }
        );
    }
}
