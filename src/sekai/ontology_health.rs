//! Ontology health score (#1463): one 0-100 score per part, and a total that
//! is the lowest available part, so a failing part is never averaged away.
//!
//! The parts are computed from signals the caller may see. A part the server
//! cannot compute, or the caller may not see, is unavailable and leaves the
//! total. This module scores signals; `GetOntologyHealth` gathers them.

use std::collections::BTreeSet;

use serde_json::Value;

pub const PART_FRESHNESS: &str = "freshness";
pub const PART_QUALITY: &str = "quality";
pub const PART_CONTRACT: &str = "contract";
pub const PART_LINT: &str = "lint";
pub const PART_TRUST: &str = "trust";
pub const PART_ACCESS: &str = "access";

/// Problems named per part, worst first; the score still counts them all.
pub const MAX_PROBLEMS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub subject_kind: String,
    pub subject_id: String,
    pub code: String,
}

impl Problem {
    pub fn new(subject_kind: &str, subject_id: &str, code: &str) -> Self {
        Self {
            subject_kind: subject_kind.into(),
            subject_id: subject_id.into(),
            code: code.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub part: &'static str,
    /// `None` when unavailable; `unavailable_reason` then says why.
    pub score: Option<u8>,
    pub unavailable_reason: &'static str,
    pub problems: Vec<Problem>,
    /// False when the inputs were capped: the score may be too high.
    pub complete: bool,
}

impl Part {
    pub fn unavailable(part: &'static str, reason: &'static str) -> Self {
        Self {
            part,
            score: None,
            unavailable_reason: reason,
            problems: Vec::new(),
            complete: true,
        }
    }

    /// The share of `total` subjects without a problem, as 0-100.
    pub fn ratio(
        part: &'static str,
        total: usize,
        mut problems: Vec<Problem>,
        complete: bool,
    ) -> Self {
        let bad = problems
            .iter()
            .map(|problem| (&problem.subject_kind, &problem.subject_id))
            .collect::<BTreeSet<_>>()
            .len()
            .min(total);
        problems.truncate(MAX_PROBLEMS);
        Self {
            part,
            score: Some(share(total, bad)),
            unavailable_reason: "",
            problems,
            complete,
        }
    }
}

/// The share of `total` that is not `bad` (at most `total`), as 0-100; 100
/// when there is nothing to score.
fn share(total: usize, bad: usize) -> u8 {
    ((total - bad) * 100)
        .checked_div(total)
        .map_or(100, |score| score as u8)
}

/// The lowest available part, or `None` when no part is available.
pub fn total(parts: &[Part]) -> Option<u8> {
    parts.iter().filter_map(|part| part.score).min()
}

/// What one visible dataset of the namespace shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatasetSignals {
    pub id: String,
    /// A firing late-schedule alert, or a latest freshness check that failed.
    pub stale: bool,
    /// Quarantined, or a latest non-freshness check that failed.
    pub failing_check: bool,
}

pub fn freshness(datasets: &[DatasetSignals], complete: bool) -> Part {
    let problems = datasets
        .iter()
        .filter(|dataset| dataset.stale)
        .map(|dataset| Problem::new("dataset", &dataset.id, "stale"))
        .collect();
    Part::ratio(PART_FRESHNESS, datasets.len(), problems, complete)
}

pub fn quality(datasets: &[DatasetSignals], complete: bool) -> Part {
    let problems = datasets
        .iter()
        .filter(|dataset| dataset.failing_check)
        .map(|dataset| Problem::new("dataset", &dataset.id, "check_failed"))
        .collect();
    Part::ratio(PART_QUALITY, datasets.len(), problems, complete)
}

/// A blocking consumer binding, as the contract part reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundTarget {
    /// The binding's object id.
    pub id: String,
    /// `None` when the binding is malformed or its digest is stale.
    pub target: Option<(String, String, String)>,
}

/// Blocking bindings whose member, or bound property, the published revision
/// no longer has: a contract an approved major revision broke. A binding
/// that cannot be verified counts too.
pub fn contract(
    bindings: &[BoundTarget],
    members: &[crate::sekai::definition_branch::DefinitionMember],
) -> Part {
    let problems = bindings
        .iter()
        .filter_map(|binding| {
            let Some((kind, id, property)) = &binding.target else {
                return Some(Problem::new("binding", &binding.id, "unverifiable"));
            };
            let member = members
                .iter()
                .find(|member| &member.member_kind == kind && &member.member_id == id);
            match member {
                None => Some(Problem::new("binding", &binding.id, "member_removed")),
                Some(member) if !property.is_empty() && !has_property(member, property) => {
                    Some(Problem::new("binding", &binding.id, "property_removed"))
                }
                Some(_) => None,
            }
        })
        .collect();
    Part::ratio(PART_CONTRACT, bindings.len(), problems, true)
}

fn has_property(
    member: &crate::sekai::definition_branch::DefinitionMember,
    property: &str,
) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(&member.definition_json) else {
        return false;
    };
    match value.get("properties") {
        Some(Value::Array(names)) => names.iter().any(|name| name.as_str() == Some(property)),
        Some(Value::Object(names)) => names.contains_key(property),
        _ => false,
    }
}

/// One lint finding, as the lint part reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub severity: String,
}

/// The share of published members (`(member_kind, member_id)`) with no
/// warning or error. Findings about anything else, such as a marking or an
/// object, and informational findings are named but do not lower the score.
pub fn lint(members: &BTreeSet<(String, String)>, findings: &[Finding], complete: bool) -> Part {
    // Errors and warnings lower the score; information does not.
    let lowers = |finding: &&Finding| finding.severity != "info";
    let mut problems: Vec<Problem> = findings
        .iter()
        .filter(lowers)
        .chain(findings.iter().filter(|finding| !lowers(finding)))
        .map(|finding| Problem::new(&finding.subject_kind, &finding.subject_id, &finding.rule))
        .collect();
    let warned = findings
        .iter()
        .filter(lowers)
        .map(|finding| (finding.subject_kind.clone(), finding.subject_id.clone()))
        .filter(|subject| members.contains(subject))
        .collect::<BTreeSet<_>>()
        .len();
    problems.truncate(MAX_PROBLEMS);
    Part {
        part: PART_LINT,
        score: Some(share(members.len(), warned)),
        unavailable_reason: "",
        problems,
        complete,
    }
}

/// Grants on the namespace and its objects: one past its end date, or one
/// without the terms the namespace policy requires and no recorded
/// exception, is a problem.
pub fn access(
    grants: &[crate::sekai::security::Grant],
    require_terms: bool,
    now_ms: i64,
    complete: bool,
) -> Part {
    let problems = grants
        .iter()
        .filter_map(|grant| {
            if grant.not_after_ms != 0 && grant.not_after_ms <= now_ms {
                Some(Problem::new("grant", &grant.id, "expired"))
            } else if require_terms
                && (grant.purpose.is_empty() || grant.not_after_ms == 0)
                && grant.exception_reason.is_empty()
            {
                Some(Problem::new("grant", &grant.id, "unreviewed"))
            } else {
                None
            }
        })
        .collect();
    Part::ratio(PART_ACCESS, grants.len(), problems, complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::DefinitionMemberInput;

    fn member(
        kind: &str,
        id: &str,
        json: &str,
    ) -> crate::sekai::definition_branch::DefinitionMember {
        DefinitionMemberInput {
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare("health")
        .unwrap()
    }

    #[test]
    fn total_is_the_lowest_available_part() {
        let parts = [
            Part::ratio(
                PART_FRESHNESS,
                4,
                vec![Problem::new("dataset", "d", "stale")],
                true,
            ),
            Part::ratio(PART_QUALITY, 0, Vec::new(), true),
            Part::unavailable(PART_TRUST, "not_stored"),
        ];
        assert_eq!(parts[0].score, Some(75));
        assert_eq!(parts[1].score, Some(100));
        assert_eq!(total(&parts), Some(75));
        assert_eq!(total(&parts[2..]), None);
    }

    #[test]
    fn stale_and_failing_datasets_lower_their_own_parts() {
        let datasets = [
            DatasetSignals {
                id: "orders".into(),
                stale: true,
                failing_check: false,
            },
            DatasetSignals {
                id: "customers".into(),
                ..Default::default()
            },
        ];
        assert_eq!(freshness(&datasets, true).score, Some(50));
        assert_eq!(quality(&datasets, true).score, Some(100));
        assert_eq!(freshness(&datasets, true).problems[0].subject_id, "orders");
    }

    #[test]
    fn a_contract_breaks_when_its_member_or_property_is_gone() {
        let members = [member(
            "object_type",
            "Order",
            r#"{"name":"Order","properties":["total"]}"#,
        )];
        let bound = |id: &str, member: &str, property: &str| BoundTarget {
            id: id.into(),
            target: Some(("object_type".into(), member.into(), property.into())),
        };
        let part = contract(
            &[
                bound("ok", "Order", "total"),
                bound("gone-property", "Order", "tax"),
                bound("gone-member", "Invoice", ""),
                BoundTarget {
                    id: "forged".into(),
                    target: None,
                },
            ],
            &members,
        );
        assert_eq!(part.score, Some(25));
        let codes: Vec<&str> = part.problems.iter().map(|p| p.code.as_str()).collect();
        assert_eq!(
            codes,
            ["property_removed", "member_removed", "unverifiable"]
        );
    }

    #[test]
    fn lint_counts_warned_members_and_names_info() {
        let finding = |rule: &str, id: &str, severity: &str| Finding {
            rule: rule.into(),
            subject_kind: "object_type".into(),
            subject_id: id.into(),
            severity: severity.into(),
        };
        let members = ["Note", "Ticket", "User", "Order"]
            .map(|id| ("object_type".to_string(), id.to_string()))
            .into();
        let mut broad = finding("broad_marking_applied", "restricted", "warning");
        broad.subject_kind = "marking".into();
        let part = lint(
            &members,
            &[
                finding("orphan_object", "o-1", "info"),
                finding("unowned_object_type", "Note", "warning"),
                finding("orphan_object_type", "User", "error"),
                broad,
            ],
            true,
        );
        // Note warned and User errored: two of four members lowered.
        assert_eq!(part.score, Some(50));
        assert_eq!(part.problems[0].code, "unowned_object_type");
        assert_eq!(part.problems.len(), 4);
    }

    #[test]
    fn expired_and_unreviewed_grants_are_access_problems() {
        let grant = |id: &str, purpose: &str, not_after_ms: i64, exception: &str| {
            crate::sekai::security::Grant {
                id: id.into(),
                purpose: purpose.into(),
                not_after_ms,
                exception_reason: exception.into(),
                ..Default::default()
            }
        };
        let grants = [
            grant("expired", "audit", 5, ""),
            grant("open", "", 0, ""),
            grant("excepted", "", 0, "break-glass"),
            grant("termed", "audit", 50, ""),
        ];
        assert_eq!(access(&grants, false, 10, true).score, Some(75));
        let part = access(&grants, true, 10, true);
        assert_eq!(part.score, Some(50));
        assert_eq!(part.problems[1].code, "unreviewed");
    }
}
