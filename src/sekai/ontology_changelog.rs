//! Ontology changelog: plain-language entries for published definition
//! revisions and policy activations, for a reader and a time window (#1471).
//!
//! Entries are derived on read from records the plane already keeps (merged
//! definition proposals, revision diffs, consumer bindings, the current
//! object-security activation). Nothing new is stored.

use crate::sekai::definition_diff::{
    DefinitionMemberChange, DefinitionRevisionCompatibility, DefinitionRevisionDiff,
};

/// Longest window one changelog request covers.
pub const MAX_CHANGELOG_WINDOW_MS: i64 = 31 * 24 * 60 * 60 * 1000;
/// Namespaces one changelog request covers.
pub const MAX_CHANGELOG_NAMESPACES: usize = 50;
/// Published revisions in the window per namespace; more fail closed.
pub const MAX_CHANGELOG_REVISIONS: usize = 200;
/// History rows scanned per namespace to reach the window; more fail closed.
pub const MAX_CHANGELOG_SCAN: usize = 5_000;

pub const CHANGE_DEFINITION_REVISION: &str = "definition_revision";
pub const CHANGE_POLICY_ACTIVATION: &str = "policy_activation";

pub fn validate_window(since_ms: i64, until_ms: i64) -> Result<(), String> {
    if since_ms < 0 || until_ms <= since_ms {
        return Err("until_ms must be after since_ms".into());
    }
    if until_ms - since_ms > MAX_CHANGELOG_WINDOW_MS {
        return Err("a changelog window covers at most 31 days".into());
    }
    Ok(())
}

/// Keep only the changes and reasons for members `can_read` accepts, and the
/// worst class among the kept reasons. A reader learns nothing about members
/// they cannot read, not even whether they changed.
pub fn visible_changes(
    compatibility: &DefinitionRevisionCompatibility,
    can_read: impl Fn(&str, &str) -> bool,
) -> (DefinitionRevisionDiff, String) {
    let keep = |changes: &[DefinitionMemberChange]| -> Vec<DefinitionMemberChange> {
        changes
            .iter()
            .filter(|change| can_read(&change.member_kind, &change.member_id))
            .cloned()
            .collect()
    };
    let diff = &compatibility.diff;
    let visible = DefinitionRevisionDiff {
        from_revision_digest: diff.from_revision_digest.clone(),
        to_revision_digest: diff.to_revision_digest.clone(),
        diff_digest: diff.diff_digest.clone(),
        added: keep(&diff.added),
        removed: keep(&diff.removed),
        changed: keep(&diff.changed),
    };
    let rank = |class: &str| match class {
        "compatible" => 0,
        "conditional" => 1,
        "breaking" => 2,
        _ => 3,
    };
    let class = compatibility
        .reasons
        .iter()
        .filter(|reason| can_read(&reason.member_kind, &reason.member_id))
        .map(|reason| reason.class.as_str())
        .max_by_key(|class| rank(class))
        .unwrap_or("compatible")
        .to_string();
    (visible, class)
}

/// One line per added, removed or changed member of a revision diff.
pub fn summarize(diff: &DefinitionRevisionDiff) -> Vec<String> {
    let member = |change: &DefinitionMemberChange| {
        format!(
            "{} {}",
            change.member_kind.replace('_', " "),
            change.member_id
        )
    };
    let list = |label: &str, items: &[String]| {
        (!items.is_empty()).then(|| format!("{label} {}", items.join(", ")))
    };
    let added = diff.added.iter().map(|c| format!("added {}", member(c)));
    let removed = diff
        .removed
        .iter()
        .map(|c| format!("removed {}", member(c)));
    let changed = diff.changed.iter().map(|change| {
        let parts: Vec<String> = [
            list("added properties", &change.added_properties),
            list("removed properties", &change.removed_properties),
            list("changed properties", &change.changed_properties),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            format!("changed {}", member(change))
        } else {
            format!("changed {}: {}", member(change), parts.join("; "))
        }
    });
    added.chain(removed).chain(changed).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(kind: &str, id: &str) -> DefinitionMemberChange {
        DefinitionMemberChange {
            member_kind: kind.into(),
            member_id: id.into(),
            from_member_digest: String::new(),
            to_member_digest: String::new(),
            added_properties: Vec::new(),
            removed_properties: Vec::new(),
            changed_properties: Vec::new(),
        }
    }

    #[test]
    fn summaries_read_as_plain_language() {
        let diff = DefinitionRevisionDiff {
            from_revision_digest: "a".into(),
            to_revision_digest: "b".into(),
            diff_digest: "d".into(),
            added: vec![change("object_type", "Invoice")],
            removed: vec![change("link_type", "billed")],
            changed: vec![DefinitionMemberChange {
                added_properties: vec!["due".into()],
                removed_properties: vec!["total".into(), "tax".into()],
                ..change("object_type", "Customer")
            }],
        };
        assert_eq!(
            summarize(&diff),
            [
                "added object type Invoice",
                "removed link type billed",
                "changed object type Customer: added properties due; removed properties total, tax",
            ]
        );
    }

    #[test]
    fn hidden_members_leave_no_change_or_class() {
        let compatibility = DefinitionRevisionCompatibility {
            from_revision_digest: "a".into(),
            to_revision_digest: "b".into(),
            compatibility_digest: "c".into(),
            class: "breaking".into(),
            reasons: vec![
                crate::sekai::definition_diff::DefinitionCompatibilityReason {
                    class: "breaking".into(),
                    member_kind: "object_type".into(),
                    member_id: "Salary".into(),
                    code: "property_removed".into(),
                    property: "amount".into(),
                },
                crate::sekai::definition_diff::DefinitionCompatibilityReason {
                    class: "compatible".into(),
                    member_kind: "object_type".into(),
                    member_id: "Invoice".into(),
                    code: "member_added".into(),
                    property: String::new(),
                },
            ],
            diff: DefinitionRevisionDiff {
                from_revision_digest: "a".into(),
                to_revision_digest: "b".into(),
                diff_digest: "d".into(),
                added: vec![change("object_type", "Invoice")],
                removed: Vec::new(),
                changed: vec![change("object_type", "Salary")],
            },
        };
        let (visible, class) = visible_changes(&compatibility, |_, id| id != "Salary");
        assert_eq!(summarize(&visible), ["added object type Invoice"]);
        assert_eq!(class, "compatible");
        let (all, class) = visible_changes(&compatibility, |_, _| true);
        assert_eq!(summarize(&all).len(), 2);
        assert_eq!(class, "breaking");
    }

    #[test]
    fn windows_are_bounded() {
        assert!(validate_window(0, 1).is_ok());
        assert!(validate_window(5, 5).is_err());
        assert!(validate_window(0, MAX_CHANGELOG_WINDOW_MS + 1).is_err());
    }
}
