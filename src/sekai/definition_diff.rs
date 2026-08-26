//! Deterministic differences and compatibility classes for definition revisions.
//!
//! Reports are content-bound: they name added, removed, and changed members
//! and property keys without returning definition bodies. Compatibility uses
//! a worst-wins class of compatible, conditional, breaking, or unknown.
//! Unknown constructs fail closed. Callers must authorize both revisions
//! before invoking this.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::sekai::definition_branch::{
    DefinitionMember, DefinitionRevision, validate_digest, validate_namespace,
    validate_revision_members,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefinitionMemberChange {
    pub member_kind: String,
    pub member_id: String,
    pub from_member_digest: String,
    pub to_member_digest: String,
    pub added_properties: Vec<String>,
    pub removed_properties: Vec<String>,
    pub changed_properties: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefinitionRevisionDiff {
    pub from_revision_digest: String,
    pub to_revision_digest: String,
    pub diff_digest: String,
    pub added: Vec<DefinitionMemberChange>,
    pub removed: Vec<DefinitionMemberChange>,
    pub changed: Vec<DefinitionMemberChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionCompatibilityClass {
    Compatible,
    Conditional,
    Breaking,
    Unknown,
}

impl DefinitionCompatibilityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Conditional => "conditional",
            Self::Breaking => "breaking",
            Self::Unknown => "unknown",
        }
    }

    fn severity(self) -> u8 {
        match self {
            Self::Compatible => 0,
            Self::Conditional => 1,
            Self::Breaking => 2,
            Self::Unknown => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefinitionCompatibilityReason {
    pub class: String,
    pub member_kind: String,
    pub member_id: String,
    pub code: String,
    pub property: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefinitionRevisionCompatibility {
    pub from_revision_digest: String,
    pub to_revision_digest: String,
    pub compatibility_digest: String,
    pub class: String,
    pub reasons: Vec<DefinitionCompatibilityReason>,
    pub diff: DefinitionRevisionDiff,
}

pub fn compare_definition_revisions(
    from: &DefinitionRevision,
    from_members: &[DefinitionMember],
    to: &DefinitionRevision,
    to_members: &[DefinitionMember],
) -> Result<DefinitionRevisionDiff, String> {
    validate_namespace(&from.namespace)?;
    validate_namespace(&to.namespace)?;
    if from.namespace != to.namespace {
        return Err(
            "definition_revision_conflict: compared revisions must share a namespace".into(),
        );
    }
    validate_digest("from_revision_digest", &from.revision_digest)?;
    validate_digest("to_revision_digest", &to.revision_digest)?;
    from.verify()?;
    to.verify()?;
    validate_revision_members(from, from_members)?;
    validate_revision_members(to, to_members)?;

    let from_map = member_map(from_members)?;
    let to_map = member_map(to_members)?;
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut identities = BTreeSet::new();
    identities.extend(from_map.keys().cloned());
    identities.extend(to_map.keys().cloned());
    for identity in identities {
        match (from_map.get(&identity), to_map.get(&identity)) {
            (None, Some(member)) => added.push(member_addition(member)?),
            (Some(member), None) => removed.push(member_removal(member)?),
            (Some(left), Some(right)) if left.member_digest != right.member_digest => {
                changed.push(member_change(left, right)?);
            }
            (Some(_), Some(_)) => {}
            (None, None) => {}
        }
    }

    let mut diff = DefinitionRevisionDiff {
        from_revision_digest: from.revision_digest.clone(),
        to_revision_digest: to.revision_digest.clone(),
        diff_digest: String::new(),
        added,
        removed,
        changed,
    };
    diff.diff_digest = diff_digest(&diff)?;
    Ok(diff)
}

pub fn classify_definition_revision_compatibility(
    from: &DefinitionRevision,
    from_members: &[DefinitionMember],
    to: &DefinitionRevision,
    to_members: &[DefinitionMember],
) -> Result<DefinitionRevisionCompatibility, String> {
    let diff = compare_definition_revisions(from, from_members, to, to_members)?;
    let from_map = member_map(from_members)?;
    let to_map = member_map(to_members)?;
    // One or more reasons per compare change. Size is already bounded by the
    // revision member and definition-byte ceilings; reasons never include bodies.
    let mut reasons = Vec::new();
    for change in &diff.added {
        let member = to_map
            .get(&(change.member_kind.clone(), change.member_id.clone()))
            .ok_or_else(|| "definition compare encountered an unknown construct".to_string())?;
        inspect_member_constructs(member)?;
        reasons.push(added_member_reason(change));
        push_unknown_fields(change, member, &mut reasons)?;
    }
    for change in &diff.removed {
        let member = from_map
            .get(&(change.member_kind.clone(), change.member_id.clone()))
            .ok_or_else(|| "definition compare encountered an unknown construct".to_string())?;
        inspect_member_constructs(member)?;
        reasons.push(reason(
            DefinitionCompatibilityClass::Breaking,
            change,
            "removed_member",
            "",
        ));
    }
    for change in &diff.changed {
        let from_member = from_map
            .get(&(change.member_kind.clone(), change.member_id.clone()))
            .ok_or_else(|| "definition compare encountered an unknown construct".to_string())?;
        let to_member = to_map
            .get(&(change.member_kind.clone(), change.member_id.clone()))
            .ok_or_else(|| "definition compare encountered an unknown construct".to_string())?;
        classify_member_change(change, from_member, to_member, &mut reasons)?;
    }
    reasons.sort_by(|left, right| {
        (
            &left.member_kind,
            &left.member_id,
            &left.code,
            &left.property,
        )
            .cmp(&(
                &right.member_kind,
                &right.member_id,
                &right.code,
                &right.property,
            ))
    });
    let class = reasons
        .iter()
        .filter_map(|item| parse_class(&item.class))
        .max_by_key(|item| item.severity())
        .unwrap_or(DefinitionCompatibilityClass::Compatible);
    let mut compatibility = DefinitionRevisionCompatibility {
        from_revision_digest: diff.from_revision_digest.clone(),
        to_revision_digest: diff.to_revision_digest.clone(),
        compatibility_digest: String::new(),
        class: class.as_str().to_string(),
        reasons,
        diff,
    };
    compatibility.compatibility_digest = compatibility_digest(&compatibility)?;
    Ok(compatibility)
}

fn added_member_reason(change: &DefinitionMemberChange) -> DefinitionCompatibilityReason {
    match change.member_kind.as_str() {
        "action_type" => reason(
            DefinitionCompatibilityClass::Conditional,
            change,
            "added_action_type",
            "",
        ),
        "function" => reason(
            DefinitionCompatibilityClass::Conditional,
            change,
            "added_function",
            "",
        ),
        "control" => reason(
            DefinitionCompatibilityClass::Conditional,
            change,
            "added_control",
            "",
        ),
        "object_type" | "interface_type" | "ontology_class" | "ontology_relation" | "link_type" => {
            reason(
                DefinitionCompatibilityClass::Compatible,
                change,
                "added_member",
                "",
            )
        }
        _ => reason(
            DefinitionCompatibilityClass::Unknown,
            change,
            "unknown_member_kind",
            "",
        ),
    }
}

fn classify_member_change(
    change: &DefinitionMemberChange,
    from: &DefinitionMember,
    to: &DefinitionMember,
    reasons: &mut Vec<DefinitionCompatibilityReason>,
) -> Result<(), String> {
    let from_value = parse_definition(&from.definition_json)?;
    let to_value = parse_definition(&to.definition_json)?;
    inspect_value_constructs(&from_value)?;
    inspect_value_constructs(&to_value)?;
    let from_required = named_string_set(&from_value, "required")?;
    let to_required = named_string_set(&to_value, "required")?;
    let from_marking = optional_string_field(&from_value, "access_marking")?;
    let to_marking = optional_string_field(&to_value, "access_marking")?;
    let mut classified = false;
    for property in &change.removed_properties {
        reasons.push(reason(
            DefinitionCompatibilityClass::Breaking,
            change,
            "removed_property",
            property,
        ));
        classified = true;
    }
    for property in &change.added_properties {
        if to_required.contains(property) {
            reasons.push(reason(
                DefinitionCompatibilityClass::Breaking,
                change,
                "added_required_property",
                property,
            ));
        } else {
            reasons.push(reason(
                DefinitionCompatibilityClass::Compatible,
                change,
                "added_optional_property",
                property,
            ));
        }
        classified = true;
    }
    for property in to_required.difference(&from_required) {
        if !change.added_properties.contains(property) {
            reasons.push(reason(
                DefinitionCompatibilityClass::Breaking,
                change,
                "added_required_property",
                property,
            ));
            classified = true;
        }
    }
    for property in from_required.difference(&to_required) {
        if !change.removed_properties.contains(property) {
            reasons.push(reason(
                DefinitionCompatibilityClass::Compatible,
                change,
                "removed_required_constraint",
                property,
            ));
            classified = true;
        }
    }
    if from_marking != to_marking {
        reasons.push(reason(
            DefinitionCompatibilityClass::Conditional,
            change,
            "changed_marking",
            "access_marking",
        ));
        classified = true;
    }
    let unknown_fields = unknown_definition_fields(&from_value)?
        .into_iter()
        .chain(unknown_definition_fields(&to_value)?)
        .collect::<BTreeSet<_>>();
    for field in &unknown_fields {
        reasons.push(reason(
            DefinitionCompatibilityClass::Unknown,
            change,
            "unknown_field_change",
            field,
        ));
        classified = true;
    }
    for field in &change.changed_properties {
        match field.as_str() {
            "required" | "access_marking" => {}
            "name" | "mode" => {
                reasons.push(reason(
                    DefinitionCompatibilityClass::Conditional,
                    change,
                    "changed_field",
                    field,
                ));
                classified = true;
            }
            _ if unknown_fields.contains(field) => {}
            _ => {
                reasons.push(reason(
                    DefinitionCompatibilityClass::Unknown,
                    change,
                    "unknown_field_change",
                    field,
                ));
                classified = true;
            }
        }
    }
    if !classified {
        reasons.push(reason(
            DefinitionCompatibilityClass::Unknown,
            change,
            "unclassified_member_change",
            "",
        ));
    }
    Ok(())
}

fn inspect_member_constructs(member: &DefinitionMember) -> Result<(), String> {
    inspect_value_constructs(&parse_definition(&member.definition_json)?)
}

const KNOWN_DEFINITION_FIELDS: &[&str] =
    &["access_marking", "mode", "name", "properties", "required"];

fn push_unknown_fields(
    change: &DefinitionMemberChange,
    member: &DefinitionMember,
    reasons: &mut Vec<DefinitionCompatibilityReason>,
) -> Result<(), String> {
    let value = parse_definition(&member.definition_json)?;
    for field in unknown_definition_fields(&value)? {
        reasons.push(reason(
            DefinitionCompatibilityClass::Unknown,
            change,
            "unknown_field_change",
            &field,
        ));
    }
    Ok(())
}

fn unknown_definition_fields(value: &Value) -> Result<Vec<String>, String> {
    let object = value.as_object().ok_or_else(|| {
        "unknown_definition_construct: definition_json must be an object".to_string()
    })?;
    Ok(object
        .keys()
        .filter(|key| !KNOWN_DEFINITION_FIELDS.contains(&key.as_str()))
        .cloned()
        .collect())
}

fn inspect_value_constructs(value: &Value) -> Result<(), String> {
    named_string_set(value, "properties")?;
    named_string_set(value, "required")?;
    optional_string_field(value, "access_marking")?;
    Ok(())
}

fn reason(
    class: DefinitionCompatibilityClass,
    change: &DefinitionMemberChange,
    code: &str,
    property: &str,
) -> DefinitionCompatibilityReason {
    DefinitionCompatibilityReason {
        class: class.as_str().to_string(),
        member_kind: change.member_kind.clone(),
        member_id: change.member_id.clone(),
        code: code.to_string(),
        property: property.to_string(),
    }
}

fn parse_class(class: &str) -> Option<DefinitionCompatibilityClass> {
    match class {
        "compatible" => Some(DefinitionCompatibilityClass::Compatible),
        "conditional" => Some(DefinitionCompatibilityClass::Conditional),
        "breaking" => Some(DefinitionCompatibilityClass::Breaking),
        "unknown" => Some(DefinitionCompatibilityClass::Unknown),
        _ => None,
    }
}

fn member_map(
    members: &[DefinitionMember],
) -> Result<BTreeMap<(String, String), &DefinitionMember>, String> {
    let mut map = BTreeMap::new();
    for member in members {
        member.verify()?;
        let key = (member.member_kind.clone(), member.member_id.clone());
        if map.insert(key, member).is_some() {
            return Err("definition revision contains duplicate member identities".into());
        }
    }
    Ok(map)
}

fn member_addition(member: &DefinitionMember) -> Result<DefinitionMemberChange, String> {
    Ok(DefinitionMemberChange {
        member_kind: member.member_kind.clone(),
        member_id: member.member_id.clone(),
        from_member_digest: String::new(),
        to_member_digest: member.member_digest.clone(),
        added_properties: property_names(&member.definition_json)?,
        removed_properties: Vec::new(),
        changed_properties: Vec::new(),
    })
}

fn member_removal(member: &DefinitionMember) -> Result<DefinitionMemberChange, String> {
    Ok(DefinitionMemberChange {
        member_kind: member.member_kind.clone(),
        member_id: member.member_id.clone(),
        from_member_digest: member.member_digest.clone(),
        to_member_digest: String::new(),
        added_properties: Vec::new(),
        removed_properties: property_names(&member.definition_json)?,
        changed_properties: Vec::new(),
    })
}

fn member_change(
    from: &DefinitionMember,
    to: &DefinitionMember,
) -> Result<DefinitionMemberChange, String> {
    let from_value = parse_definition(&from.definition_json)?;
    let to_value = parse_definition(&to.definition_json)?;
    let from_props = property_set(&from_value)?;
    let to_props = property_set(&to_value)?;
    let added_properties = to_props.difference(&from_props).cloned().collect();
    let removed_properties = from_props.difference(&to_props).cloned().collect();
    let mut changed_properties = BTreeSet::new();
    let from_object = from_value.as_object().ok_or_else(|| {
        "unknown_definition_construct: definition_json must be an object".to_string()
    })?;
    let to_object = to_value.as_object().ok_or_else(|| {
        "unknown_definition_construct: definition_json must be an object".to_string()
    })?;
    let mut keys = BTreeSet::new();
    keys.extend(from_object.keys().cloned());
    keys.extend(to_object.keys().cloned());
    for key in keys {
        if key == "properties" {
            continue;
        }
        if from_object.get(&key) != to_object.get(&key) {
            changed_properties.insert(key);
        }
    }
    Ok(DefinitionMemberChange {
        member_kind: from.member_kind.clone(),
        member_id: from.member_id.clone(),
        from_member_digest: from.member_digest.clone(),
        to_member_digest: to.member_digest.clone(),
        added_properties,
        removed_properties,
        changed_properties: changed_properties.into_iter().collect(),
    })
}

fn parse_definition(definition_json: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(definition_json)
        .map_err(|error| format!("unknown_definition_construct: {error}"))?;
    if !value.is_object() {
        return Err("unknown_definition_construct: definition_json must be an object".into());
    }
    Ok(value)
}

fn property_names(definition_json: &str) -> Result<Vec<String>, String> {
    let value = parse_definition(definition_json)?;
    Ok(property_set(&value)?.into_iter().collect())
}

fn property_set(value: &Value) -> Result<BTreeSet<String>, String> {
    named_string_set(value, "properties")
}

fn named_string_set(value: &Value, key: &str) -> Result<BTreeSet<String>, String> {
    let Some(items) = value.get(key) else {
        return Ok(BTreeSet::new());
    };
    let Some(array) = items.as_array() else {
        return Err(format!(
            "unknown_definition_construct: {key} must be an array of strings"
        ));
    };
    let mut names = BTreeSet::new();
    for item in array {
        let Some(name) = item.as_str() else {
            return Err(format!(
                "unknown_definition_construct: {key} must be an array of strings"
            ));
        };
        if !names.insert(name.to_string()) {
            return Err(format!(
                "unknown_definition_construct: {key} list contains duplicates"
            ));
        }
    }
    Ok(names)
}

fn optional_string_field(value: &Value, key: &str) -> Result<Option<String>, String> {
    match value.get(key) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(format!(
            "unknown_definition_construct: {key} must be a string"
        )),
    }
}

fn diff_digest(diff: &DefinitionRevisionDiff) -> Result<String, String> {
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&DiffDigestInput {
        from_revision_digest: &diff.from_revision_digest,
        to_revision_digest: &diff.to_revision_digest,
        added: &diff.added,
        removed: &diff.removed,
        changed: &diff.changed,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.definition-revision-diff/v1\n");
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[derive(Serialize)]
struct DiffDigestInput<'a> {
    from_revision_digest: &'a str,
    to_revision_digest: &'a str,
    added: &'a [DefinitionMemberChange],
    removed: &'a [DefinitionMemberChange],
    changed: &'a [DefinitionMemberChange],
}

fn compatibility_digest(report: &DefinitionRevisionCompatibility) -> Result<String, String> {
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&CompatibilityDigestInput {
        from_revision_digest: &report.from_revision_digest,
        to_revision_digest: &report.to_revision_digest,
        class: &report.class,
        reasons: &report.reasons,
        diff_digest: &report.diff.diff_digest,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.definition-revision-compatibility/v1\n");
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[derive(Serialize)]
struct CompatibilityDigestInput<'a> {
    from_revision_digest: &'a str,
    to_revision_digest: &'a str,
    class: &'a str,
    reasons: &'a [DefinitionCompatibilityReason],
    diff_digest: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };

    fn prepared(kind: &str, id: &str, json: &str) -> DefinitionMember {
        DefinitionMemberInput {
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare("team-a")
        .unwrap()
    }

    fn revision(members: &[DefinitionMember], parent: &str) -> DefinitionRevision {
        prepare_revision(
            "team-a",
            parent,
            members.iter().map(|member| DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }),
            false,
            "author",
            1,
        )
        .unwrap()
    }

    #[test]
    fn reports_added_removed_and_changed_members_in_stable_order() {
        let ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let incident = prepared(
            "object_type",
            "Incident",
            r#"{"name":"Incident","properties":["severity"]}"#,
        );
        let action = prepared("action_type", "Assign", r#"{"name":"Assign"}"#);
        let control = prepared("control", "retention", r#"{"mode":"strict"}"#);
        let updated_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title","body"]}"#,
        );
        let from_members = vec![ticket, action];
        let to_members = vec![updated_ticket, incident, control];
        let from = revision(&from_members, "");
        let to = revision(&to_members, "");
        let diff = compare_definition_revisions(&from, &from_members, &to, &to_members).unwrap();
        assert_eq!(
            diff.added
                .iter()
                .map(|change| (change.member_kind.as_str(), change.member_id.as_str()))
                .collect::<Vec<_>>(),
            [("control", "retention"), ("object_type", "Incident")]
        );
        assert_eq!(diff.removed[0].member_id, "Assign");
        assert_eq!(diff.changed[0].member_id, "Ticket");
        assert_eq!(diff.changed[0].added_properties, ["body"]);
        let replay = compare_definition_revisions(&from, &from_members, &to, &to_members).unwrap();
        assert_eq!(diff, replay);
    }

    #[test]
    fn unknown_properties_construct_fails_closed() {
        let from_member = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let to_member = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":{"title":true}}"#,
        );
        let from = revision(std::slice::from_ref(&from_member), "");
        let to = revision(std::slice::from_ref(&to_member), "");
        let error = compare_definition_revisions(
            &from,
            std::slice::from_ref(&from_member),
            &to,
            std::slice::from_ref(&to_member),
        )
        .unwrap_err();
        assert!(error.contains("unknown_definition_construct"));
    }

    #[test]
    fn added_member_with_unknown_properties_fails_closed() {
        let from_member = prepared("control", "retention", r#"{"mode":"strict"}"#);
        let to_member = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":{"title":true}}"#,
        );
        let from = revision(std::slice::from_ref(&from_member), "");
        let to = revision(std::slice::from_ref(&to_member), "");
        let error = compare_definition_revisions(
            &from,
            std::slice::from_ref(&from_member),
            &to,
            std::slice::from_ref(&to_member),
        )
        .unwrap_err();
        assert!(error.contains("unknown_definition_construct"));
        let classify_error = classify_definition_revision_compatibility(
            &from,
            std::slice::from_ref(&from_member),
            &to,
            std::slice::from_ref(&to_member),
        )
        .unwrap_err();
        assert!(classify_error.contains("unknown_definition_construct"));
    }

    #[test]
    fn identical_revisions_are_compatible() {
        let ticket = prepared("object_type", "Ticket", r#"{"name":"Ticket"}"#);
        let members = vec![ticket];
        let from = revision(&members, "");
        let to = revision(&members, "");
        let report =
            classify_definition_revision_compatibility(&from, &members, &to, &members).unwrap();
        assert_eq!(report.class, "compatible");
        assert!(report.reasons.is_empty());
        let replay =
            classify_definition_revision_compatibility(&from, &members, &to, &members).unwrap();
        assert_eq!(report, replay);
    }

    #[test]
    fn added_optional_property_and_link_are_compatible() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title","body"]}"#,
        );
        let link = prepared("link_type", "AssignedTo", r#"{"name":"AssignedTo"}"#);
        let from_members = vec![from_ticket];
        let to_members = vec![to_ticket, link];
        let from = revision(&from_members, "");
        let to = revision(&to_members, "");
        let report =
            classify_definition_revision_compatibility(&from, &from_members, &to, &to_members)
                .unwrap();
        assert_eq!(report.class, "compatible");
        assert_eq!(
            report
                .reasons
                .iter()
                .map(|reason| (reason.member_kind.as_str(), reason.code.as_str()))
                .collect::<Vec<_>>(),
            [
                ("link_type", "added_member"),
                ("object_type", "added_optional_property")
            ]
        );
    }

    #[test]
    fn required_property_and_removed_member_are_breaking() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let action = prepared("action_type", "Assign", r#"{"name":"Assign"}"#);
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title","severity"],"required":["severity"]}"#,
        );
        let from_members = vec![from_ticket, action];
        let to_members = vec![to_ticket];
        let from = revision(&from_members, "");
        let to = revision(&to_members, "");
        let report =
            classify_definition_revision_compatibility(&from, &from_members, &to, &to_members)
                .unwrap();
        assert_eq!(report.class, "breaking");
        assert!(report.reasons.iter().any(
            |reason| reason.code == "added_required_property" && reason.property == "severity"
        ));
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.code == "removed_member" && reason.member_id == "Assign")
        );
    }

    #[test]
    fn added_action_control_and_marking_are_conditional() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","access_marking":"internal"}"#,
        );
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","access_marking":"restricted"}"#,
        );
        let action = prepared("action_type", "Assign", r#"{"name":"Assign"}"#);
        let control = prepared("control", "retention", r#"{"mode":"strict"}"#);
        let from_members = vec![from_ticket];
        let to_members = vec![to_ticket, action, control];
        let from = revision(&from_members, "");
        let to = revision(&to_members, "");
        let report =
            classify_definition_revision_compatibility(&from, &from_members, &to, &to_members)
                .unwrap();
        assert_eq!(report.class, "conditional");
        assert_eq!(
            report
                .reasons
                .iter()
                .map(|reason| (reason.member_kind.as_str(), reason.code.as_str()))
                .collect::<Vec<_>>(),
            [
                ("action_type", "added_action_type"),
                ("control", "added_control"),
                ("object_type", "changed_marking")
            ]
        );
    }

    #[test]
    fn added_member_with_unknown_field_is_unknown_not_compatible() {
        let from_ticket = prepared("object_type", "Ticket", r#"{"name":"Ticket"}"#);
        let extra = prepared(
            "ontology_class",
            "Finding",
            r#"{"name":"Finding","shape":"wide"}"#,
        );
        let from_members = vec![from_ticket];
        let to_members = vec![
            prepared("object_type", "Ticket", r#"{"name":"Ticket"}"#),
            extra,
        ];
        let from = revision(&from_members, "");
        let to = revision(&to_members, "");
        let report =
            classify_definition_revision_compatibility(&from, &from_members, &to, &to_members)
                .unwrap();
        assert_eq!(report.class, "unknown");
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.code == "unknown_field_change" && reason.property == "shape")
        );
    }

    #[test]
    fn unchanged_unknown_field_keeps_changed_member_unknown() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","shape":"wide","properties":["title"]}"#,
        );
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","shape":"wide","properties":["title","body"]}"#,
        );
        let from = revision(std::slice::from_ref(&from_ticket), "");
        let to = revision(std::slice::from_ref(&to_ticket), "");
        let report = classify_definition_revision_compatibility(
            &from,
            std::slice::from_ref(&from_ticket),
            &to,
            std::slice::from_ref(&to_ticket),
        )
        .unwrap();
        assert_eq!(report.class, "unknown");
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.code == "unknown_field_change" && reason.property == "shape")
        );
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.code == "added_optional_property" && reason.property == "body")
        );
    }

    #[test]
    fn unknown_field_change_is_unknown_not_compatible() {
        let from_ticket = prepared("object_type", "Ticket", r#"{"name":"Ticket"}"#);
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","shape":"wide"}"#,
        );
        let from = revision(std::slice::from_ref(&from_ticket), "");
        let to = revision(std::slice::from_ref(&to_ticket), "");
        let report = classify_definition_revision_compatibility(
            &from,
            std::slice::from_ref(&from_ticket),
            &to,
            std::slice::from_ref(&to_ticket),
        )
        .unwrap();
        assert_eq!(report.class, "unknown");
        assert_eq!(report.reasons[0].code, "unknown_field_change");
        assert_eq!(report.reasons[0].property, "shape");
    }

    #[test]
    fn unknown_required_construct_fails_closed() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"],"required":{"title":true}}"#,
        );
        let from = revision(std::slice::from_ref(&from_ticket), "");
        let to = revision(std::slice::from_ref(&to_ticket), "");
        let error = classify_definition_revision_compatibility(
            &from,
            std::slice::from_ref(&from_ticket),
            &to,
            std::slice::from_ref(&to_ticket),
        )
        .unwrap_err();
        assert!(error.contains("unknown_definition_construct"));
    }

    #[test]
    fn worst_wins_prefers_breaking_over_compatible() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title","legacy"]}"#,
        );
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title","body"]}"#,
        );
        let from = revision(std::slice::from_ref(&from_ticket), "");
        let to = revision(std::slice::from_ref(&to_ticket), "");
        let report = classify_definition_revision_compatibility(
            &from,
            std::slice::from_ref(&from_ticket),
            &to,
            std::slice::from_ref(&to_ticket),
        )
        .unwrap();
        assert_eq!(report.class, "breaking");
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.code == "removed_property" && reason.property == "legacy")
        );
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.code == "added_optional_property" && reason.property == "body")
        );
    }
}
