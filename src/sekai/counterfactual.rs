//! Counterfactual view queries over recorded history (#1453).
//!
//! Answers "what would this object set have shown at a past time if a policy
//! or marking rule had been different". The object set is rebuilt from the
//! recorded object change log, the rules in effect then and the candidate
//! rules are both evaluated by the one policy decision point, and the result
//! is the per-principal difference. Nothing here writes or triggers Actions.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::domain::Object;
use crate::sekai::markings::{OBJECT_CLASSIFICATION_PROPERTY, PrincipalAuthority};
use crate::sekai::object_change_subscription::CommittedObjectMutation;
use crate::sekai::object_security::ObjectSecurityOperation;
use crate::sekai::policy_decision::{
    PolicyOutcome, PolicySimulationDifference, PolicySnapshot, SimulatedPrincipal,
    compile_for_snapshot, snapshot_digest,
};

/// Largest live object set one query rebuilds. Larger sets fail closed.
pub const MAX_COUNTERFACTUAL_OBJECTS: usize = 10_000;
/// Most recorded changes one query replays. Longer histories fail closed.
pub const MAX_COUNTERFACTUAL_CHANGES: usize = 200_000;

/// Object set rebuilt as of a past time.
#[derive(Debug, Clone, Default)]
pub struct ObjectsAsOf {
    /// Objects that existed at the time, with their values then, by id.
    pub objects: Vec<Object>,
    /// Objects that existed at the time but whose values the log cannot
    /// rebuild (deleted since, or an unknown change). They are left out of
    /// both views rather than guessed.
    pub unreconstructable: Vec<String>,
}

enum Reverted {
    Present(Object),
    Absent,
    Unknown,
}

/// Whether the retained change log reaches back to `as_of_ms`. Retention
/// deletes the oldest changes by time, so a time before the oldest retained
/// change may have lost the changes that would revert live values.
pub fn history_covers(changes: &[CommittedObjectMutation], as_of_ms: i64) -> bool {
    changes
        .iter()
        .map(|mutation| mutation.change.timestamp)
        .min()
        .is_some_and(|oldest| oldest <= as_of_ms)
}

/// Rebuild `namespace` as of `as_of_ms` from the live objects and the
/// recorded changes, by reverting every change stamped after `as_of_ms`
/// newest commit first. Objects with no change after `as_of_ms` are as they are now.
pub fn objects_as_of(
    namespace: &str,
    live: &[Object],
    changes: &[CommittedObjectMutation],
    as_of_ms: i64,
) -> ObjectsAsOf {
    let mut later: BTreeMap<&str, Vec<&CommittedObjectMutation>> = BTreeMap::new();
    for mutation in changes.iter().filter(|m| m.change.timestamp > as_of_ms) {
        later
            .entry(mutation.change.object_id.as_str())
            .or_default()
            .push(mutation);
    }
    let live_by_id: HashMap<&str, &Object> = live.iter().map(|o| (o.id.as_str(), o)).collect();
    let ids: BTreeSet<&str> = live_by_id
        .keys()
        .copied()
        .chain(later.keys().copied())
        .collect();

    let mut rebuilt = ObjectsAsOf::default();
    for id in ids {
        let mut state = match live_by_id.get(id) {
            Some(object) => Reverted::Present((*object).clone()),
            None => Reverted::Absent,
        };
        let mut history = later.remove(id).unwrap_or_default();
        // Commit order, not timestamps: writers' clocks may disagree.
        history.sort_by_key(|m| m.seq);
        for mutation in history.into_iter().rev() {
            state = revert(state, mutation);
        }
        match state {
            Reverted::Present(object) if object.namespace == namespace => {
                rebuilt.objects.push(object)
            }
            Reverted::Present(_) | Reverted::Absent => {}
            Reverted::Unknown => rebuilt.unreconstructable.push(id.into()),
        }
    }
    rebuilt
}

fn revert(state: Reverted, mutation: &CommittedObjectMutation) -> Reverted {
    let change = &mutation.change;
    match change.field.as_str() {
        "_created" => Reverted::Absent,
        // A delete keeps kind and name but no property values.
        "_deleted" => Reverted::Unknown,
        "_namespace" | "_security_snapshot" | "_security_kind" => state,
        field if field.starts_with("_security_property.") => state,
        field => {
            let Reverted::Present(mut object) = state else {
                return Reverted::Unknown;
            };
            match field {
                "kind" => object.kind = change.old_value.clone(),
                "name" => object.name = change.old_value.clone(),
                "namespace" => object.namespace = change.old_value.clone(),
                "external_id" => object.external_id = change.old_value.clone(),
                _ => {
                    let Some(key) = field.strip_prefix("properties.") else {
                        return Reverted::Unknown;
                    };
                    // The diff records an absent property as an empty value.
                    if change.old_value.is_empty() {
                        object.properties.remove(key);
                    } else {
                        object
                            .properties
                            .insert(key.into(), change.old_value.clone());
                    }
                }
            }
            Reverted::Present(object)
        }
    }
}

/// Candidate marking rule: objects of `kind` whose properties equal every
/// entry of `property_equals` carry `marking` instead of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MarkingRule {
    pub kind: String,
    pub property_equals: BTreeMap<String, String>,
    pub marking: String,
}

impl MarkingRule {
    pub fn matches(&self, object: &Object) -> bool {
        object.kind == self.kind
            && self
                .property_equals
                .iter()
                .all(|(key, value)| object.properties.get(key) == Some(value))
    }

    /// Return `objects` with this rule's marking applied.
    pub fn apply(&self, objects: &[Object]) -> Vec<Object> {
        objects
            .iter()
            .cloned()
            .map(|mut object| {
                if self.matches(&object) {
                    object
                        .properties
                        .insert(OBJECT_CLASSIFICATION_PROPERTY.into(), self.marking.clone());
                }
                object
            })
            .collect()
    }
}

/// One principal's view at the past time, as it was and as it would have been.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrincipalCounterfactualView {
    pub principal: String,
    pub actual_visible: Vec<String>,
    pub counterfactual_visible: Vec<String>,
    /// Visible then, hidden under the candidate.
    pub hidden: Vec<String>,
    /// Hidden then, visible under the candidate.
    pub revealed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CounterfactualReport {
    pub namespace: String,
    pub as_of_ms: i64,
    pub actual_digest: String,
    pub candidate_digest: String,
    pub views: Vec<PrincipalCounterfactualView>,
    /// Object and property outcomes that differ, sorted by principal, object
    /// and property. An empty property is the whole object.
    pub differences: Vec<PolicySimulationDifference>,
    pub unreconstructable: Vec<String>,
    /// Digest of the evaluated object set, principals, ACL denials and time.
    pub input_digest: String,
    /// Digest of the whole report, `input_digest` included; equal inputs give
    /// an equal digest.
    pub report_digest: String,
}

/// One rule set: a policy snapshot and whether the namespace is activated.
/// In an activated namespace a kind without a policy is denied, as on reads.
#[derive(Clone, Copy)]
pub struct Rules<'a> {
    pub snapshot: &'a PolicySnapshot,
    pub activated: bool,
}

impl Rules<'_> {
    fn decide(
        &self,
        principal: &SimulatedPrincipal,
        object: &Object,
        operation: ObjectSecurityOperation,
        at_ms: i64,
    ) -> Result<(PolicyOutcome, BTreeSet<String>), String> {
        if self.activated && !self.snapshot.policies.contains_key(&object.kind) {
            return Ok((PolicyOutcome::Deny, BTreeSet::new()));
        }
        let access =
            compile_for_snapshot(self.snapshot, principal, &object.kind, operation, at_ms)?;
        Ok((
            access.decide(object).outcome,
            access.visible_property_names(object),
        ))
    }
}

/// Inputs to one counterfactual evaluation, already rebuilt and resolved.
pub struct CounterfactualInput<'a> {
    pub as_of: &'a ObjectsAsOf,
    pub principals: &'a [SimulatedPrincipal],
    pub actual: Rules<'a>,
    pub candidate: Rules<'a>,
    pub marking_rule: Option<&'a MarkingRule>,
    /// `(principal, object_id)` pairs an object ACL denies. ACLs are not
    /// candidates, so they deny on both sides.
    pub acl_denied: &'a BTreeSet<(String, String)>,
    pub operation: ObjectSecurityOperation,
    pub as_of_ms: i64,
}

/// Evaluate every principal against the object set as it was at `as_of_ms`
/// under the actual rules and under the candidate rules. Pure and
/// deterministic: no I/O, no clock, outputs sorted.
pub fn evaluate_counterfactual(
    input: CounterfactualInput<'_>,
) -> Result<CounterfactualReport, String> {
    if input.actual.snapshot.namespace != input.candidate.snapshot.namespace {
        return Err("counterfactual requires one namespace".into());
    }
    let actual_objects = &input.as_of.objects;
    let candidate_objects = match input.marking_rule {
        Some(rule) => rule.apply(actual_objects),
        None => actual_objects.clone(),
    };
    let mut principals: Vec<&SimulatedPrincipal> = input.principals.iter().collect();
    principals.sort_by(|left, right| left.principal.cmp(&right.principal));
    principals.dedup_by(|left, right| left.principal == right.principal);

    let mut views = Vec::new();
    let mut differences = Vec::new();
    for principal in principals {
        let mut actual_visible = Vec::new();
        let mut counterfactual_visible = Vec::new();
        for (then, candidate) in actual_objects.iter().zip(&candidate_objects) {
            let acl_allows = !input
                .acl_denied
                .contains(&(principal.principal.clone(), then.id.clone()));
            let decide = |rules: Rules<'_>, object: &Object| {
                if acl_allows {
                    rules.decide(principal, object, input.operation, input.as_of_ms)
                } else {
                    Ok((PolicyOutcome::Deny, BTreeSet::new()))
                }
            };
            let (then_outcome, then_properties) = decide(input.actual, then)?;
            let (candidate_outcome, candidate_properties) = decide(input.candidate, candidate)?;
            if then_outcome == PolicyOutcome::Allow {
                actual_visible.push(then.id.clone());
            }
            if candidate_outcome == PolicyOutcome::Allow {
                counterfactual_visible.push(candidate.id.clone());
            }
            let difference =
                |property: &str, current_outcome, candidate_outcome| PolicySimulationDifference {
                    principal: principal.principal.clone(),
                    object_id: then.id.clone(),
                    object_kind: then.kind.clone(),
                    property: property.into(),
                    current_outcome,
                    candidate_outcome,
                };
            if then_outcome != candidate_outcome {
                differences.push(difference("", then_outcome, candidate_outcome));
            }
            for property in then_properties.symmetric_difference(&candidate_properties) {
                let outcome = |visible: &BTreeSet<String>| {
                    if visible.contains(property) {
                        PolicyOutcome::Allow
                    } else {
                        PolicyOutcome::Deny
                    }
                };
                differences.push(difference(
                    property,
                    outcome(&then_properties),
                    outcome(&candidate_properties),
                ));
            }
        }
        let then: BTreeSet<&String> = actual_visible.iter().collect();
        let candidate: BTreeSet<&String> = counterfactual_visible.iter().collect();
        views.push(PrincipalCounterfactualView {
            principal: principal.principal.clone(),
            hidden: then
                .difference(&candidate)
                .map(|id| (*id).clone())
                .collect(),
            revealed: candidate
                .difference(&then)
                .map(|id| (*id).clone())
                .collect(),
            actual_visible,
            counterfactual_visible,
        });
    }

    let mut report = CounterfactualReport {
        namespace: input.actual.snapshot.namespace.clone(),
        as_of_ms: input.as_of_ms,
        actual_digest: rules_digest(input.actual, None)?,
        candidate_digest: rules_digest(input.candidate, input.marking_rule)?,
        views,
        differences,
        unreconstructable: input.as_of.unreconstructable.clone(),
        input_digest: input_digest(&input)?,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;
    Ok(report)
}

fn rules_digest(rules: Rules<'_>, marking_rule: Option<&MarkingRule>) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.counterfactual-rules/v1\0");
    hasher.update(snapshot_digest(rules.snapshot)?.as_bytes());
    hasher.update([0, u8::from(rules.activated), 0]);
    hasher.update(serde_json::to_vec(&marking_rule).map_err(|error| error.to_string())?);
    Ok(format!("{:x}", hasher.finalize()))
}

fn input_digest(input: &CounterfactualInput<'_>) -> Result<String, String> {
    #[derive(Serialize)]
    struct ObjectThen<'a> {
        id: &'a str,
        kind: &'a str,
        name: &'a str,
        namespace: &'a str,
        external_id: &'a str,
        properties: BTreeMap<&'a str, &'a str>,
    }
    #[derive(Serialize)]
    struct PrincipalInput<'a> {
        principal: &'a str,
        context_digest: String,
        authority: &'a PrincipalAuthority,
        namespace_granted: bool,
    }
    #[derive(Serialize)]
    struct Inputs<'a> {
        as_of_ms: i64,
        operation: &'a str,
        objects: Vec<ObjectThen<'a>>,
        unreconstructable: &'a [String],
        principals: Vec<PrincipalInput<'a>>,
        acl_denied: &'a BTreeSet<(String, String)>,
    }
    let objects = input
        .as_of
        .objects
        .iter()
        .map(|object| ObjectThen {
            id: &object.id,
            kind: &object.kind,
            name: &object.name,
            namespace: &object.namespace,
            external_id: &object.external_id,
            properties: object
                .properties
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect(),
        })
        .collect();
    let mut principals = input
        .principals
        .iter()
        .map(|principal| {
            Ok(PrincipalInput {
                principal: &principal.principal,
                context_digest: principal.context.digest()?,
                authority: &principal.authority,
                namespace_granted: principal.namespace_granted,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    principals.sort_by(|left, right| left.principal.cmp(right.principal));
    principals.dedup_by(|left, right| left.principal == right.principal);
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.counterfactual-input/v1\0");
    hasher.update(
        serde_json::to_vec(&Inputs {
            as_of_ms: input.as_of_ms,
            operation: input.operation.as_str(),
            objects,
            unreconstructable: &input.as_of.unreconstructable,
            principals,
            acl_denied: input.acl_denied,
        })
        .map_err(|error| error.to_string())?,
    );
    Ok(format!("{:x}", hasher.finalize()))
}

fn report_digest(report: &CounterfactualReport) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.counterfactual-report/v1\0");
    hasher.update(serde_json::to_vec(report).map_err(|error| error.to_string())?);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::object_security::PrincipalPolicyContext;
    use sekai_types::object_change::ObjectChange;

    fn object(id: &str, team: &str, marking: &str) -> Object {
        Object {
            id: id.into(),
            kind: "document".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: [("team", team), (OBJECT_CLASSIFICATION_PROPERTY, marking)]
                .into_iter()
                .filter(|(_, value)| !value.is_empty())
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            created: 1,
            updated: 1,
        }
    }

    fn change(
        seq: u64,
        object_id: &str,
        field: &str,
        old: &str,
        new: &str,
        at: i64,
    ) -> CommittedObjectMutation {
        CommittedObjectMutation {
            change: ObjectChange {
                id: format!("c{seq}"),
                object_id: object_id.into(),
                field: field.into(),
                old_value: old.into(),
                new_value: new.into(),
                changed_by: "writer".into(),
                timestamp: at,
                operation_id: String::new(),
                ..Default::default()
            },
            seq,
            object_kind: "document".into(),
            object_namespace: "acme".into(),
        }
    }

    fn principal(name: &str, ceiling: Option<&str>) -> SimulatedPrincipal {
        SimulatedPrincipal {
            principal: name.into(),
            context: PrincipalPolicyContext {
                delegated_subject: None,
                subjects: vec![name.into()],
                scopes: Vec::new(),
            }
            .normalized(),
            authority: PrincipalAuthority {
                principal: name.into(),
                classification_ceiling: ceiling
                    .map(|token| crate::sekai::markings::parse_classification(token).unwrap()),
                classification_token: ceiling.map(Into::into),
                allowed_purposes: BTreeSet::new(),
                declassify_markings: BTreeSet::new(),
            },
            purpose: None,
            purpose_authorization: None,
            namespace_granted: true,
        }
    }

    fn legacy() -> PolicySnapshot {
        PolicySnapshot {
            namespace: "acme".into(),
            activation_digest: "legacy".into(),
            policies: BTreeMap::new(),
            lattice: None,
        }
    }

    /// Live state after a recorded history: `fin` was internal at t=100 and
    /// declassified at t=200, `new` was created at t=200, `gone` existed at
    /// t=100 and was deleted at t=200.
    fn history() -> (Vec<Object>, Vec<CommittedObjectMutation>) {
        let live = vec![
            object("fin", "finance", "public"),
            object("ops", "ops", ""),
            object("new", "finance", "public"),
        ];
        let changes = vec![
            change(1, "fin", "_created", "", "document/fin", 10),
            change(2, "fin", "properties.access_marking", "", "internal", 10),
            change(3, "gone", "_created", "", "document/gone", 20),
            change(
                4,
                "fin",
                "properties.access_marking",
                "internal",
                "public",
                200,
            ),
            change(5, "new", "_created", "", "document/new", 200),
            change(6, "gone", "_deleted", "document/gone", "", 200),
            change(7, "gone", "_namespace", "acme", "", 200),
        ];
        (live, changes)
    }

    #[test]
    fn as_of_reverts_later_changes_and_leaves_deleted_objects_out() {
        let (live, changes) = history();
        let then = objects_as_of("acme", &live, &changes, 100);
        let ids: Vec<&str> = then.objects.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["fin", "ops"]);
        assert_eq!(
            then.objects[0].properties[OBJECT_CLASSIFICATION_PROPERTY],
            "internal"
        );
        assert_eq!(then.unreconstructable, ["gone"]);

        let now = objects_as_of("acme", &live, &changes, 300);
        let mut sorted = live.clone();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(now.objects.len(), sorted.len());
        assert!(
            now.objects
                .iter()
                .zip(&sorted)
                .all(|(rebuilt, live)| rebuilt.id == live.id
                    && rebuilt.persisted_state_matches(live))
        );
        assert!(now.unreconstructable.is_empty());
    }

    #[test]
    fn history_must_reach_back_to_the_requested_time() {
        let (_, changes) = history();
        assert!(history_covers(&changes, 100));
        assert!(history_covers(&changes, 10));
        assert!(!history_covers(&changes, 9));
        assert!(!history_covers(&[], 100));
    }

    #[test]
    fn as_of_fails_closed_on_unknown_change_fields() {
        let live = vec![object("fin", "finance", "public")];
        let changes = vec![change(1, "fin", "unknown_field", "a", "b", 200)];
        let then = objects_as_of("acme", &live, &changes, 100);
        assert!(then.objects.is_empty());
        assert_eq!(then.unreconstructable, ["fin"]);
    }

    #[test]
    fn tighter_marking_hides_exactly_the_matching_objects_from_principals_below_it() {
        let (live, changes) = history();
        let then = objects_as_of("acme", &live, &changes, 100);
        let principals = [
            principal("bob", Some("restricted")),
            principal("alice", Some("confidential")),
            principal("carol", None),
        ];
        let rule = MarkingRule {
            kind: "document".into(),
            property_equals: BTreeMap::from([("team".into(), "finance".into())]),
            marking: "restricted".into(),
        };
        let snapshot = legacy();
        let legacy_rules = Rules {
            snapshot: &snapshot,
            activated: false,
        };
        let no_acl = BTreeSet::new();
        let input = || CounterfactualInput {
            as_of: &then,
            principals: &principals,
            actual: legacy_rules,
            candidate: legacy_rules,
            acl_denied: &no_acl,
            marking_rule: Some(&rule),
            operation: ObjectSecurityOperation::Read,
            as_of_ms: 100,
        };
        let report = evaluate_counterfactual(input()).unwrap();

        let view = |name: &str| report.views.iter().find(|v| v.principal == name).unwrap();
        assert_eq!(view("alice").actual_visible, ["fin", "ops"]);
        assert_eq!(view("alice").counterfactual_visible, ["ops"]);
        assert_eq!(view("alice").hidden, ["fin"]);
        assert!(view("alice").revealed.is_empty());
        assert_eq!(view("bob").hidden, Vec::<String>::new());
        // No clearance: the internal marking already hid `fin` then.
        assert_eq!(view("carol").actual_visible, ["ops"]);
        assert!(view("carol").hidden.is_empty());
        let object_level: Vec<(&str, &str)> = report
            .differences
            .iter()
            .filter(|d| d.property.is_empty())
            .map(|d| (d.principal.as_str(), d.object_id.as_str()))
            .collect();
        assert_eq!(object_level, [("alice", "fin")]);
        assert_eq!(report.unreconstructable, ["gone"]);
        let names: Vec<&str> = report.views.iter().map(|v| v.principal.as_str()).collect();
        assert_eq!(names, ["alice", "bob", "carol"]);

        assert_eq!(evaluate_counterfactual(input()).unwrap(), report);
        let unchanged = evaluate_counterfactual(CounterfactualInput {
            marking_rule: None,
            ..input()
        })
        .unwrap();
        assert!(unchanged.differences.is_empty());
        assert_ne!(unchanged.report_digest, report.report_digest);
        let fewer = ObjectsAsOf {
            objects: then.objects[1..].to_vec(),
            unreconstructable: then.unreconstructable.clone(),
        };
        let narrowed = evaluate_counterfactual(CounterfactualInput {
            as_of: &fewer,
            ..input()
        })
        .unwrap();
        assert_ne!(narrowed.input_digest, report.input_digest);

        let acl_denied = BTreeSet::from([("alice".to_string(), "ops".to_string())]);
        let activated = Rules {
            snapshot: &snapshot,
            activated: true,
        };
        let gated = evaluate_counterfactual(CounterfactualInput {
            candidate: activated,
            acl_denied: &acl_denied,
            ..input()
        })
        .unwrap();
        let alice = gated.views.iter().find(|v| v.principal == "alice").unwrap();
        // The ACL hides `ops` on both sides; an activated candidate with no
        // policy for the kind denies everything else.
        assert_eq!(alice.actual_visible, ["fin"]);
        assert!(alice.counterfactual_visible.is_empty());
    }
}
