//! Definition change bundles (#1691, ADR 0125): one read-only view of what a
//! candidate definition revision means for data.
//!
//! A bundle pairs the revision diff with a migration plan and a declarative
//! backfill for object types. Object-type definitions name properties without
//! types, so a rename, a default for a new required property, or a type
//! change cannot be inferred from the diff; the author declares them as
//! hints. Anything the hints do not cover, and every type change or removed
//! object type, becomes a manual step instead of a guess. Generation writes,
//! publishes, and runs nothing.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::sekai::definition_branch::{DefinitionMember, DefinitionRevision};
use crate::sekai::definition_diff::{DefinitionRevisionDiff, compare_definition_revisions};

pub const BUNDLE_CONTRACT: &str = "sekai.definition-change-bundle/v1";
pub const BACKFILL_CONTRACT: &str = "sekai.definition-backfill/v1";
const OBJECT_TYPE: &str = "object_type";

/// Author-declared intent the diff cannot show.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeHints {
    pub renames: Vec<PropertyRename>,
    pub defaults: Vec<PropertyDefault>,
    pub type_changes: Vec<PropertyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyRename {
    pub object_type: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyDefault {
    pub object_type: String,
    pub property: String,
    /// The value existing objects get for a newly required property.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyRef {
    pub object_type: String,
    pub property: String,
}

/// One planned migration step. `kind` is `rename_property`,
/// `default_required_property`, `drop_property`, `type_change`, or
/// `remove_object_type`; `manual` steps carry a reason code instead of an
/// automatic plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStep {
    pub kind: String,
    pub object_type: String,
    pub property: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_property: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_value: String,
    pub manual: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Declarative backfill for one object type: target property to the source
/// property or literal that fills it on existing objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillAssignment {
    pub object_type: String,
    pub property: String,
    /// `copy` from `source`, or `default` to `source` as a literal where the
    /// property is still empty after copies.
    pub mode: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefinitionChangeBundle {
    pub contract_version: String,
    /// sha256 over the bundle with this field empty; consumer impact is
    /// caller-scoped and stays outside the digest.
    pub bundle_digest: String,
    pub diff: DefinitionRevisionDiff,
    pub steps: Vec<MigrationStep>,
    pub backfill_contract: String,
    pub backfill: Vec<BackfillAssignment>,
}

/// The string list under `key` (`properties` or `required`) of an object
/// type, or `None` when the revision has no such object type.
fn object_type_names(
    members: &[DefinitionMember],
    object_type: &str,
    key: &str,
) -> Option<BTreeSet<String>> {
    let member = members
        .iter()
        .find(|member| member.member_kind == OBJECT_TYPE && member.member_id == object_type)?;
    Some(
        serde_json::from_str::<Value>(&member.definition_json)
            .ok()
            .and_then(|definition| definition.get(key).cloned())
            .and_then(|names| serde_json::from_value::<Vec<String>>(names).ok())
            .map(|names| names.into_iter().collect())
            .unwrap_or_default(),
    )
}

fn required_properties(members: &[DefinitionMember], object_type: &str) -> BTreeSet<String> {
    object_type_names(members, object_type, "required").unwrap_or_default()
}

/// Refuses a hint list that names the same `(object type, property)` twice,
/// so the plan never depends on hint order.
fn unique<'a>(
    what: &str,
    keys: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for (object_type, property) in keys {
        if !seen.insert((object_type, property)) {
            return Err(format!(
                "{what} hints name {object_type:?}.{property:?} more than once"
            ));
        }
    }
    Ok(())
}

fn manual(kind: &str, object_type: &str, property: &str, reason: &str) -> MigrationStep {
    MigrationStep {
        kind: kind.into(),
        object_type: object_type.into(),
        property: property.into(),
        from_property: String::new(),
        default_value: String::new(),
        manual: true,
        reason: reason.into(),
    }
}

/// Builds the bundle for `from` (the published head) to `to` (the candidate).
/// Hints that do not match the diff are refused rather than ignored.
pub fn generate_change_bundle(
    from: &DefinitionRevision,
    from_members: &[DefinitionMember],
    to: &DefinitionRevision,
    to_members: &[DefinitionMember],
    hints: &ChangeHints,
) -> Result<DefinitionChangeBundle, String> {
    let diff = compare_definition_revisions(from, from_members, to, to_members)?;
    let changed = diff
        .changed
        .iter()
        .filter(|change| change.member_kind == OBJECT_TYPE)
        .map(|change| (change.member_id.as_str(), change))
        .collect::<BTreeMap<_, _>>();
    let mut steps = Vec::new();
    let mut backfill = Vec::new();
    unique(
        "rename source",
        hints
            .renames
            .iter()
            .map(|rename| (rename.object_type.as_str(), rename.from.as_str())),
    )?;
    unique(
        "rename target",
        hints
            .renames
            .iter()
            .map(|rename| (rename.object_type.as_str(), rename.to.as_str())),
    )?;
    unique(
        "default",
        hints
            .defaults
            .iter()
            .map(|default| (default.object_type.as_str(), default.property.as_str())),
    )?;
    unique(
        "type change",
        hints
            .type_changes
            .iter()
            .map(|property| (property.object_type.as_str(), property.property.as_str())),
    )?;
    // Rename target to its source.
    let mut renamed = BTreeMap::new();
    let mut consumed_removed = BTreeSet::new();

    for rename in &hints.renames {
        let change = changed.get(rename.object_type.as_str()).ok_or_else(|| {
            format!(
                "rename hint names unchanged object type {:?}",
                rename.object_type
            )
        })?;
        if !change.removed_properties.contains(&rename.from)
            || !change.added_properties.contains(&rename.to)
        {
            return Err(format!(
                "rename hint {:?} to {:?} on {:?} does not match the diff",
                rename.from, rename.to, rename.object_type
            ));
        }
        consumed_removed.insert((rename.object_type.clone(), rename.from.clone()));
        renamed.insert(
            (rename.object_type.as_str(), rename.to.as_str()),
            rename.from.as_str(),
        );
        steps.push(MigrationStep {
            kind: "rename_property".into(),
            object_type: rename.object_type.clone(),
            property: rename.to.clone(),
            from_property: rename.from.clone(),
            default_value: String::new(),
            manual: false,
            reason: String::new(),
        });
        backfill.push(BackfillAssignment {
            object_type: rename.object_type.clone(),
            property: rename.to.clone(),
            mode: "copy".into(),
            source: rename.from.clone(),
        });
    }

    let defaults = hints
        .defaults
        .iter()
        .map(|default| {
            (
                (default.object_type.as_str(), default.property.as_str()),
                default,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut used_defaults = BTreeSet::new();
    for change in changed.values() {
        // New properties and existing ones that became required both leave
        // existing objects without a value.
        let required_before = required_properties(from_members, &change.member_id);
        let newly_required = required_properties(to_members, &change.member_id)
            .difference(&required_before)
            .cloned()
            .collect::<Vec<_>>();
        for added in &newly_required {
            // A copy fills the target only where the source always had a
            // value; an optional source still needs a default.
            if renamed
                .get(&(change.member_id.as_str(), added.as_str()))
                .is_some_and(|source| required_before.contains(*source))
            {
                continue;
            }
            match defaults.get(&(change.member_id.as_str(), added.as_str())) {
                Some(default) => {
                    used_defaults.insert((change.member_id.clone(), added.clone()));
                    steps.push(MigrationStep {
                        kind: "default_required_property".into(),
                        object_type: change.member_id.clone(),
                        property: added.clone(),
                        from_property: String::new(),
                        default_value: default.value.clone(),
                        manual: false,
                        reason: String::new(),
                    });
                    backfill.push(BackfillAssignment {
                        object_type: change.member_id.clone(),
                        property: added.clone(),
                        mode: "default".into(),
                        source: default.value.clone(),
                    });
                }
                None => steps.push(manual(
                    "default_required_property",
                    &change.member_id,
                    added,
                    "required_property_without_default",
                )),
            }
        }
        for removed in &change.removed_properties {
            if !consumed_removed.contains(&(change.member_id.clone(), removed.clone())) {
                // Existing values are stripped on migration; nothing restores them.
                steps.push(manual(
                    "drop_property",
                    &change.member_id,
                    removed,
                    "property_values_dropped",
                ));
            }
        }
    }
    if let Some(unused) = hints.defaults.iter().find(|default| {
        !used_defaults.contains(&(default.object_type.clone(), default.property.clone()))
    }) {
        return Err(format!(
            "default hint for {:?}.{:?} does not match a newly required property",
            unused.object_type, unused.property
        ));
    }
    for type_change in &hints.type_changes {
        if !object_type_names(to_members, &type_change.object_type, "properties")
            .is_some_and(|properties| properties.contains(&type_change.property))
        {
            return Err(format!(
                "type change hint names {:?}.{:?}, which the candidate does not define",
                type_change.object_type, type_change.property
            ));
        }
        steps.push(manual(
            "type_change",
            &type_change.object_type,
            &type_change.property,
            "type_change_not_convertible",
        ));
    }
    for removed in diff
        .removed
        .iter()
        .filter(|change| change.member_kind == OBJECT_TYPE)
    {
        steps.push(manual(
            "remove_object_type",
            &removed.member_id,
            "",
            "object_type_removed",
        ));
    }
    steps.sort_by(|left, right| {
        (&left.object_type, &left.property, &left.kind).cmp(&(
            &right.object_type,
            &right.property,
            &right.kind,
        ))
    });
    // `copy` sorts before `default`, so a default fills only what copies left empty.
    backfill.sort_by(|left, right| {
        (&left.object_type, &left.property, &left.mode).cmp(&(
            &right.object_type,
            &right.property,
            &right.mode,
        ))
    });
    let mut bundle = DefinitionChangeBundle {
        contract_version: BUNDLE_CONTRACT.into(),
        bundle_digest: String::new(),
        diff,
        steps,
        backfill_contract: BACKFILL_CONTRACT.into(),
        backfill,
    };
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&bundle)?;
    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_CONTRACT.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical);
    bundle.bundle_digest = format!("sha256:{:x}", hasher.finalize());
    Ok(bundle)
}

/// Applies `bundle`'s backfill for `object_type` to its dataset rows
/// (#1692): copies first, then defaults where the property is still empty.
/// No column is dropped: a renamed source column stays beside its copy, so
/// dataset redaction still finds the rows by their original fields; dropping
/// it is the apply step's. `column` maps a property to its dataset column.
/// Deterministic, so a dry run rerun yields the same rows.
pub fn apply_backfill(
    bundle: &DefinitionChangeBundle,
    object_type: &str,
    rows: &[HashMap<String, String>],
    column: impl Fn(&str) -> String,
) -> Vec<HashMap<String, String>> {
    let assignments = bundle
        .backfill
        .iter()
        .filter(|assignment| assignment.object_type == object_type)
        .collect::<Vec<_>>();
    rows.iter()
        .map(|row| {
            let mut out = row.clone();
            for assignment in assignments.iter().filter(|a| a.mode == "copy") {
                if let Some(value) = row.get(&column(&assignment.source)) {
                    out.insert(column(&assignment.property), value.clone());
                }
            }
            for assignment in assignments.iter().filter(|a| a.mode == "default") {
                let target = column(&assignment.property);
                if out.get(&target).is_none_or(|value| value.is_empty()) {
                    out.insert(target, assignment.source.clone());
                }
            }
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };

    fn revision(json: &str, parent: &str) -> (DefinitionRevision, Vec<DefinitionMember>) {
        let member = DefinitionMemberInput {
            member_kind: OBJECT_TYPE.into(),
            member_id: "Ticket".into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare("ns")
        .unwrap();
        let revision = prepare_revision(
            "ns",
            parent,
            [DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }],
            parent.is_empty(),
            "author",
            1,
        )
        .unwrap();
        (revision, vec![member])
    }

    fn bundle(hints: &ChangeHints) -> Result<DefinitionChangeBundle, String> {
        let (from, from_members) =
            revision(r#"{"name":"Ticket","properties":["title","state"]}"#, "");
        let (to, to_members) = revision(
            r#"{"name":"Ticket","properties":["subject","state","priority"],"required":["priority"]}"#,
            &from.revision_digest,
        );
        generate_change_bundle(&from, &from_members, &to, &to_members, hints)
    }

    #[test]
    fn declared_rename_and_default_plan_a_backfill() {
        let generated = bundle(&ChangeHints {
            renames: vec![PropertyRename {
                object_type: "Ticket".into(),
                from: "title".into(),
                to: "subject".into(),
            }],
            defaults: vec![PropertyDefault {
                object_type: "Ticket".into(),
                property: "priority".into(),
                value: "normal".into(),
            }],
            type_changes: vec![],
        })
        .unwrap();
        assert!(
            generated.steps.iter().all(|step| !step.manual),
            "{:?}",
            generated.steps
        );
        assert_eq!(
            generated.backfill,
            vec![
                BackfillAssignment {
                    object_type: "Ticket".into(),
                    property: "priority".into(),
                    mode: "default".into(),
                    source: "normal".into(),
                },
                BackfillAssignment {
                    object_type: "Ticket".into(),
                    property: "subject".into(),
                    mode: "copy".into(),
                    source: "title".into(),
                },
            ]
        );
    }

    #[test]
    fn undeclared_changes_become_manual_steps() {
        let generated = bundle(&ChangeHints {
            type_changes: vec![PropertyRef {
                object_type: "Ticket".into(),
                property: "state".into(),
            }],
            ..ChangeHints::default()
        })
        .unwrap();
        let manual = generated
            .steps
            .iter()
            .filter(|step| step.manual)
            .map(|step| (step.property.as_str(), step.reason.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            manual,
            vec![
                ("priority", "required_property_without_default"),
                ("state", "type_change_not_convertible"),
                ("title", "property_values_dropped"),
            ]
        );
        assert!(generated.backfill.is_empty());
    }

    #[test]
    fn hints_that_do_not_match_the_diff_are_refused() {
        let wrong = ChangeHints {
            renames: vec![PropertyRename {
                object_type: "Ticket".into(),
                from: "state".into(),
                to: "subject".into(),
            }],
            ..ChangeHints::default()
        };
        assert!(bundle(&wrong).is_err());
    }

    #[test]
    fn an_existing_property_made_required_needs_a_default() {
        let (from, from_members) = revision(r#"{"name":"Ticket","properties":["state"]}"#, "");
        let (to, to_members) = revision(
            r#"{"name":"Ticket","properties":["state"],"required":["state"]}"#,
            &from.revision_digest,
        );
        let generated = generate_change_bundle(
            &from,
            &from_members,
            &to,
            &to_members,
            &ChangeHints::default(),
        )
        .unwrap();
        assert_eq!(generated.steps.len(), 1);
        assert_eq!(
            generated.steps[0].reason,
            "required_property_without_default"
        );
    }

    #[test]
    fn renaming_an_optional_property_to_a_required_one_needs_a_default() {
        let (from, from_members) = revision(r#"{"name":"Ticket","properties":["title"]}"#, "");
        let (to, to_members) = revision(
            r#"{"name":"Ticket","properties":["subject"],"required":["subject"]}"#,
            &from.revision_digest,
        );
        let rename = PropertyRename {
            object_type: "Ticket".into(),
            from: "title".into(),
            to: "subject".into(),
        };
        let undeclared = generate_change_bundle(
            &from,
            &from_members,
            &to,
            &to_members,
            &ChangeHints {
                renames: vec![rename.clone()],
                ..ChangeHints::default()
            },
        )
        .unwrap();
        assert!(
            undeclared
                .steps
                .iter()
                .any(|step| step.reason == "required_property_without_default")
        );
        let declared = generate_change_bundle(
            &from,
            &from_members,
            &to,
            &to_members,
            &ChangeHints {
                renames: vec![rename],
                defaults: vec![PropertyDefault {
                    object_type: "Ticket".into(),
                    property: "subject".into(),
                    value: "untitled".into(),
                }],
                type_changes: vec![],
            },
        )
        .unwrap();
        let modes = declared
            .backfill
            .iter()
            .map(|assignment| assignment.mode.as_str())
            .collect::<Vec<_>>();
        assert_eq!(modes, ["copy", "default"]);
    }

    #[test]
    fn colliding_or_unknown_hints_are_refused() {
        let collide = ChangeHints {
            renames: vec![
                PropertyRename {
                    object_type: "Ticket".into(),
                    from: "title".into(),
                    to: "subject".into(),
                },
                PropertyRename {
                    object_type: "Ticket".into(),
                    from: "state".into(),
                    to: "subject".into(),
                },
            ],
            ..ChangeHints::default()
        };
        assert!(bundle(&collide).unwrap_err().contains("rename target"));
        let unknown = ChangeHints {
            type_changes: vec![PropertyRef {
                object_type: "Ticket".into(),
                property: "missing".into(),
            }],
            ..ChangeHints::default()
        };
        assert!(bundle(&unknown).is_err());
    }

    #[test]
    fn backfill_renames_then_defaults_on_dataset_rows() {
        let generated = bundle(&ChangeHints {
            renames: vec![PropertyRename {
                object_type: "Ticket".into(),
                from: "title".into(),
                to: "subject".into(),
            }],
            defaults: vec![PropertyDefault {
                object_type: "Ticket".into(),
                property: "priority".into(),
                value: "normal".into(),
            }],
            type_changes: vec![],
        })
        .unwrap();
        let rows = vec![
            HashMap::from([
                ("id".to_string(), "1".to_string()),
                ("title".to_string(), "Broken".to_string()),
            ]),
            HashMap::from([
                ("id".to_string(), "2".to_string()),
                ("title".to_string(), "Slow".to_string()),
                ("priority".to_string(), "high".to_string()),
            ]),
        ];
        let after = apply_backfill(&generated, "Ticket", &rows, str::to_owned);
        assert_eq!(after[0]["subject"], "Broken");
        // The source column stays for redaction; the apply step drops it.
        assert_eq!(after[0]["title"], "Broken");
        assert_eq!(after[0]["priority"], "normal");
        // A value already present is kept.
        assert_eq!(after[1]["priority"], "high");
        assert_eq!(
            after,
            apply_backfill(&generated, "Ticket", &rows, str::to_owned)
        );
    }

    #[test]
    fn a_rename_onto_its_own_mapped_column_keeps_the_values() {
        let generated = bundle(&ChangeHints {
            renames: vec![PropertyRename {
                object_type: "Ticket".into(),
                from: "title".into(),
                to: "subject".into(),
            }],
            defaults: vec![PropertyDefault {
                object_type: "Ticket".into(),
                property: "priority".into(),
                value: "normal".into(),
            }],
            type_changes: vec![],
        })
        .unwrap();
        // Both properties map to the same column.
        let column = |property: &str| match property {
            "title" | "subject" => "subject".to_string(),
            other => other.to_string(),
        };
        let rows = vec![HashMap::from([("subject".to_string(), "Kept".to_string())])];
        let after = apply_backfill(&generated, "Ticket", &rows, column);
        assert_eq!(after[0]["subject"], "Kept");
    }
}
