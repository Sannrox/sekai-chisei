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
//! - enabled Action types with no instance the caller may see;
//! - object type properties no visible consumer binding references (#1684).
//!
//! A definition member can suppress findings about itself (or its
//! properties) with a reason, in its `lint_suppressions`; a suppressed
//! finding is still reported, marked with that reason. Suppressions live in
//! the definition, so they are versioned and reviewed with proposals.
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
pub const RULE_UNREFERENCED_PROPERTY: &str = "unreferenced_property";

/// Definition field holding a member's suppressions.
pub const SUPPRESSIONS_FIELD: &str = "lint_suppressions";
const MAX_SUPPRESSIONS: usize = 64;
const MAX_SUPPRESSION_REASON: usize = 512;
/// Rules a member can suppress about itself, by member kind.
const SUPPRESSIBLE: &[(&str, &str)] = &[
    ("object_type", RULE_ORPHAN_OBJECT_TYPE),
    ("object_type", RULE_UNOWNED_OBJECT_TYPE),
    ("object_type", RULE_UNREFERENCED_PROPERTY),
    ("link_type", RULE_UNOWNED_LINK_TYPE),
];

/// Error findings a definition proposal introduces block its merge (#1687).
pub const SEVERITY_ERROR: &str = "error";
pub const SEVERITY_WARNING: &str = "warning";
pub const LINT_GATE: &str = "definition_lint_gate";
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
    /// For `property` findings, the property of the object type
    /// `subject_id`; empty otherwise.
    pub property: String,
    pub severity: &'static str,
    pub detail: String,
    /// The reason of the suppression covering this finding, if any.
    pub suppressed: Option<String>,
}

/// One entry of a member's `lint_suppressions`: the rule, the property for
/// a property rule, and a required reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub rule: String,
    #[serde(default)]
    pub property: String,
    pub reason: String,
}

/// The suppressions a definition declares, validated: a known rule this
/// member kind can raise, a property exactly for the property rule, and a
/// non-empty reason.
pub fn suppressions(
    member_kind: &str,
    definition: &serde_json::Value,
) -> Result<Vec<Suppression>, String> {
    let Some(raw) = definition.get(SUPPRESSIONS_FIELD) else {
        return Ok(Vec::new());
    };
    let entries: Vec<Suppression> = serde_json::from_value(raw.clone()).map_err(|error| {
        format!("{SUPPRESSIONS_FIELD} must be a list of {{rule, property, reason}}: {error}")
    })?;
    if entries.len() > MAX_SUPPRESSIONS {
        return Err(format!(
            "{SUPPRESSIONS_FIELD} holds at most {MAX_SUPPRESSIONS} entries"
        ));
    }
    for entry in &entries {
        if !SUPPRESSIBLE.contains(&(member_kind, entry.rule.as_str())) {
            return Err(format!(
                "{SUPPRESSIONS_FIELD}: a {member_kind} cannot suppress {:?}",
                entry.rule
            ));
        }
        if (entry.rule == RULE_UNREFERENCED_PROPERTY) == entry.property.trim().is_empty() {
            return Err(format!(
                "{SUPPRESSIONS_FIELD}: name a property exactly for {RULE_UNREFERENCED_PROPERTY}"
            ));
        }
        let reason = entry.reason.trim();
        if reason.is_empty() || reason.len() > MAX_SUPPRESSION_REASON {
            return Err(format!(
                "{SUPPRESSIONS_FIELD}: every suppression needs a reason of 1 to {MAX_SUPPRESSION_REASON} bytes"
            ));
        }
    }
    Ok(entries)
}

/// Consumer references as `(member_kind, member_id)` or `(object_type,
/// property)` pairs.
pub type References = BTreeSet<(String, String)>;

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
    pub consumed: References,
    /// `(object_type, property)` referenced by a visible consumer binding.
    pub consumed_properties: References,
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
        property: String::new(),
        severity,
        detail,
        suppressed: None,
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

/// The report: every finding, capped at [`MAX_FINDINGS`].
pub fn lint(input: &LintInput) -> LintReport {
    let mut findings = lint_all(input);
    let complete = input.objects_complete && findings.len() <= MAX_FINDINGS;
    findings.truncate(MAX_FINDINGS);
    LintReport { findings, complete }
}

/// Every finding, sorted and marked with its suppression; uncapped, so a
/// gate never misses one.
pub fn lint_all(input: &LintInput) -> Vec<LintFinding> {
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
                SEVERITY_ERROR,
                "no visible object of this type is linked, and no consumer references it".into(),
            ));
        }
        let properties = serde_json::from_str::<serde_json::Value>(&object_type.definition_json)
            .ok()
            .and_then(|value| value.get("properties").cloned())
            .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
            .unwrap_or_default();
        for property in properties {
            if !input
                .consumed_properties
                .contains(&(id.clone(), property.clone()))
            {
                findings.push(LintFinding {
                    property,
                    ..finding(
                        RULE_UNREFERENCED_PROPERTY,
                        "property",
                        id,
                        SEVERITY_WARNING,
                        "no visible consumer binding references this property".into(),
                    )
                });
            }
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
    suppress(&input.members, &mut findings);
    findings.sort();
    findings
}

/// Marks every finding a definition member suppresses about itself or one
/// of its properties. Invalid suppressions never reach a published revision,
/// so one that fails to parse here suppresses nothing.
fn suppress(members: &[DefinitionMember], findings: &mut [LintFinding]) {
    let mut declared: BTreeMap<(&str, &str), Vec<Suppression>> = BTreeMap::new();
    for member in members {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&member.definition_json) else {
            continue;
        };
        if let Ok(entries) = suppressions(&member.member_kind, &value) {
            declared.insert((&member.member_kind, &member.member_id), entries);
        }
    }
    for finding in findings {
        let member_kind = match finding.subject_kind {
            "property" => "object_type",
            kind => kind,
        };
        let (member_id, property) = (finding.subject_id.as_str(), finding.property.as_str());
        finding.suppressed = declared
            .get(&(member_kind, member_id))
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.rule == finding.rule && entry.property == property)
            })
            .map(|entry| entry.reason.trim().to_string());
    }
}

/// The definition-level findings `candidate` introduces over `base`: the
/// rules that read only members and consumer references, evaluated on both
/// revisions with the same references, keeping the candidate's findings the
/// base does not have in the same suppression state. A finding already
/// present and unsuppressed before the proposal never blocks it; one whose
/// suppression the proposal removes does.
pub fn introduced_findings(
    base: &[DefinitionMember],
    candidate: &[DefinitionMember],
    consumed: &References,
    consumed_properties: &References,
) -> Vec<LintFinding> {
    let definition_only = |members: &[DefinitionMember]| {
        lint_all(&LintInput {
            members: members.to_vec(),
            // No data: a type counts as linked only through a consumer.
            objects_complete: true,
            consumed: consumed.clone(),
            consumed_properties: consumed_properties.clone(),
            ..LintInput::default()
        })
    };
    let key = |finding: &LintFinding| {
        (
            finding.rule,
            finding.subject_kind,
            finding.subject_id.clone(),
            finding.property.clone(),
            // Removing a suppression counts as introducing the finding.
            finding.suppressed.is_some(),
        )
    };
    let before: BTreeSet<_> = definition_only(base).iter().map(key).collect();
    definition_only(candidate)
        .into_iter()
        .filter(|finding| !before.contains(&key(finding)))
        .collect()
}

/// Refuses a merge whose candidate introduces an unsuppressed error
/// finding, naming each one. Reads every consumer reference: the gate is
/// the system's decision, not a caller's view.
pub fn require_definition_lint(
    base: &[DefinitionMember],
    candidate: &[DefinitionMember],
    consumed: &References,
    consumed_properties: &References,
) -> Result<(), String> {
    let blocking: Vec<String> = introduced_findings(base, candidate, consumed, consumed_properties)
        .into_iter()
        .filter(|finding| finding.severity == SEVERITY_ERROR && finding.suppressed.is_none())
        .map(|finding| format!("{} {}", finding.rule, finding.subject_id))
        .collect();
    if blocking.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{LINT_GATE}: {} (fix, or add a lint_suppressions entry with a reason)",
            blocking.join(", ")
        ))
    }
}

/// Consumer references held by binding objects whose declaration digest
/// still matches, as `(member_kind, member_id)` and `(object_type,
/// property)`.
pub fn consumer_references(bindings: &[Object]) -> (References, References) {
    let mut consumed = BTreeSet::new();
    let mut consumed_properties = BTreeSet::new();
    for binding in bindings
        .iter()
        .filter_map(|object| {
            crate::sekai::definition_consumer_impact::binding_from_object(object).ok()
        })
        // A binding edited since it was declared references nothing.
        .filter(|binding| {
            binding.declaration_digest
                == crate::sekai::definition_consumer_impact::binding_digest(binding)
        })
    {
        if binding.member_kind == "object_type" && !binding.property.is_empty() {
            consumed_properties.insert((binding.member_id.clone(), binding.property));
        }
        consumed.insert((binding.member_kind, binding.member_id));
    }
    (consumed, consumed_properties)
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
    fn a_property_no_consumer_references_is_reported_until_one_does() {
        let mut input = clean();
        input.members[0] = member(
            "object_type",
            "Ticket",
            r#"{"owner":"support","properties":["title","legacy"]}"#,
        );
        input
            .consumed_properties
            .insert(("Ticket".into(), "title".into()));
        let report = lint(&input);
        let ids: Vec<(&str, &str)> = report
            .findings
            .iter()
            .map(|finding| (finding.subject_id.as_str(), finding.property.as_str()))
            .collect();
        assert_eq!(ids, [("Ticket", "legacy")]);
        assert_eq!(report.findings[0].rule, RULE_UNREFERENCED_PROPERTY);
        input
            .consumed_properties
            .insert(("Ticket".into(), "legacy".into()));
        assert!(lint(&input).findings.is_empty());
    }

    #[test]
    fn a_suppressed_finding_is_still_reported_with_its_reason() {
        let mut input = clean();
        input.members[0] = member(
            "object_type",
            "Ticket",
            r#"{"owner":"support","properties":["legacy"],"lint_suppressions":[{"rule":"unreferenced_property","property":"legacy","reason":"read by the nightly export"}]}"#,
        );
        input.members.push(member(
            "link_type",
            "Mentions",
            r#"{"lint_suppressions":[{"rule":"unowned_link_type","reason":"retiring"}]}"#,
        ));
        let report = lint(&input);
        let suppressed: Vec<(&str, Option<&str>)> = report
            .findings
            .iter()
            .map(|finding| (finding.subject_id.as_str(), finding.suppressed.as_deref()))
            .collect();
        assert_eq!(
            suppressed,
            [
                ("Mentions", Some("retiring")),
                ("Ticket", Some("read by the nightly export")),
            ]
        );
    }

    #[test]
    fn a_property_suppression_matches_its_own_type_even_with_dotted_ids() {
        let mut input = clean();
        input.members.push(member(
            "object_type",
            "support.Ticket",
            r#"{"owner":"support","properties":["legacy"],"lint_suppressions":[{"rule":"unreferenced_property","property":"legacy","reason":"kept"},{"rule":"orphan_object_type","reason":"seed"}]}"#,
        ));
        // A type named like the prefix must not lend its suppression.
        input.members.push(member(
            "object_type",
            "support",
            r#"{"owner":"support","properties":["Ticket.legacy"],"lint_suppressions":[{"rule":"orphan_object_type","reason":"seed"}]}"#,
        ));
        let report = lint(&input);
        let property: Vec<(&str, Option<&str>)> = report
            .findings
            .iter()
            .filter(|finding| finding.rule == RULE_UNREFERENCED_PROPERTY)
            .map(|finding| (finding.subject_id.as_str(), finding.suppressed.as_deref()))
            .collect();
        assert_eq!(
            property,
            [("support", None), ("support.Ticket", Some("kept"))]
        );
    }

    #[test]
    fn a_suppression_needs_a_reason_and_a_rule_its_member_raises() {
        let check = |kind: &str, json: &str| {
            suppressions(kind, &serde_json::from_str(json).unwrap()).map(|entries| entries.len())
        };
        assert_eq!(
            check(
                "object_type",
                r#"{"lint_suppressions":[{"rule":"orphan_object_type","reason":"seed type"}]}"#
            ),
            Ok(1)
        );
        for (kind, json) in [
            (
                "object_type",
                r#"{"lint_suppressions":[{"rule":"orphan_object_type"}]}"#,
            ),
            (
                "object_type",
                r#"{"lint_suppressions":[{"rule":"orphan_object_type","reason":" "}]}"#,
            ),
            (
                "link_type",
                r#"{"lint_suppressions":[{"rule":"orphan_object_type","reason":"x"}]}"#,
            ),
            (
                "object_type",
                r#"{"lint_suppressions":[{"rule":"unreferenced_property","reason":"x"}]}"#,
            ),
            (
                "object_type",
                r#"{"lint_suppressions":[{"rule":"orphan_object","reason":"x"}]}"#,
            ),
            (
                "object_type",
                r#"{"lint_suppressions":{"rule":"orphan_object_type"}}"#,
            ),
        ] {
            assert!(check(kind, json).is_err(), "{kind} {json}");
        }
        // Preparing a member rejects it before it can reach a revision.
        let rejected = crate::sekai::definition_branch::DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"lint_suppressions":[{"rule":"orphan_object_type"}]}"#.into(),
            member_digest: String::new(),
        }
        .prepare("acme");
        assert!(rejected.is_err());
    }

    #[test]
    fn the_gate_sees_an_introduced_error_past_the_report_cap() {
        let base: Vec<DefinitionMember> = (0..MAX_FINDINGS)
            .map(|n| member("object_type", &format!("a-{n:04}"), r#"{"owner":"o"}"#))
            .collect();
        let mut candidate = base.clone();
        candidate.push(member("object_type", "z-new", r#"{"owner":"o"}"#));
        let refused =
            require_definition_lint(&base, &candidate, &BTreeSet::new(), &BTreeSet::new())
                .unwrap_err();
        assert!(refused.contains("orphan_object_type z-new"), "{refused}");
    }

    #[test]
    fn removing_a_suppression_reintroduces_the_finding() {
        let suppressed = vec![member(
            "object_type",
            "Note",
            r#"{"owner":"o","lint_suppressions":[{"rule":"orphan_object_type","reason":"kept"}]}"#,
        )];
        let bare = vec![member("object_type", "Note", r#"{"owner":"o"}"#)];
        let none = BTreeSet::new();
        assert!(require_definition_lint(&suppressed, &bare, &none, &none).is_err());
        assert!(require_definition_lint(&suppressed, &suppressed, &none, &none).is_ok());
        assert!(require_definition_lint(&bare, &bare, &none, &none).is_ok());
    }

    #[test]
    fn a_binding_edited_since_its_declaration_references_nothing() {
        use crate::sekai::definition_consumer_impact::{
            BINDING_CONTRACT, BINDING_KIND, binding_digest, binding_from_object,
        };
        let mut binding = Object {
            id: "b-1".into(),
            kind: BINDING_KIND.into(),
            name: "b-1".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: [
                ("contract_version", BINDING_CONTRACT),
                ("owner", "team"),
                ("resource_identity", "dashboard"),
                ("member_kind", "object_type"),
                ("member_id", "Ticket"),
                ("declaration_digest", "pending"),
                ("source_locator", "dashboards/1"),
            ]
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .into(),
            created: 0,
            updated: 0,
        };
        binding.properties.insert(
            "declaration_digest".into(),
            binding_digest(&binding_from_object(&binding).unwrap()),
        );
        assert_eq!(
            consumer_references(std::slice::from_ref(&binding)).0.len(),
            1
        );
        binding
            .properties
            .insert("member_id".into(), "Orphan".into());
        assert!(consumer_references(&[binding]).0.is_empty());
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
