//! Deterministic differences between two governed definition revisions.
//!
//! The report is content-bound: it names added, removed, and changed members
//! and property keys without returning definition bodies. Unknown constructs
//! fail closed. Callers must authorize both revisions before invoking this.

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
    let Some(properties) = value.get("properties") else {
        return Ok(BTreeSet::new());
    };
    let Some(items) = properties.as_array() else {
        return Err("unknown_definition_construct: properties must be an array of strings".into());
    };
    let mut names = BTreeSet::new();
    for item in items {
        let Some(name) = item.as_str() else {
            return Err(
                "unknown_definition_construct: properties must be an array of strings".into(),
            );
        };
        if !names.insert(name.to_string()) {
            return Err("unknown_definition_construct: properties list contains duplicates".into());
        }
    }
    Ok(names)
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
    }
}
