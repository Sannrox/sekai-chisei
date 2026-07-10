//! Governed capability authoring.
//!
//! A capability proposal groups an agent spec, its action allowlist, a seed eval suite, and a
//! routing policy. Authoring is deliberately side-effect free: proposals are review artifacts,
//! not registered agents or live routing changes.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chisei::eval::{Assertion, Case, Suite};
use crate::chisei::evolve::{self, TaskRecord};

pub const MIN_RECURRING_TASKS: usize = 3;
pub const MIN_SUCCESSFUL_TASKS: usize = 2;
pub const MAX_SEED_EVAL_CASES: usize = 8;

pub const PROPOSAL_AWAITING_REVIEW: &str = "awaiting_review";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityObservation {
    pub task: TaskRecord,
    pub task_class: String,
    /// Governed action type names used by this task. Unknown action types are never copied into a
    /// proposal, even when an observation claims they were used.
    pub action_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSpec {
    pub name: String,
    pub namespace: String,
    pub task_class: String,
    pub instructions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRoutingPolicy {
    pub task_class: String,
    /// Optional concrete model learned from affinity/routing history. Empty means the normal
    /// capable-tier policy remains in control.
    pub preferred_model: String,
    pub fallback_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProposal {
    pub id: String,
    pub namespace: String,
    pub task_class: String,
    pub agent_spec: AgentSpec,
    pub allowed_action_types: Vec<String>,
    pub eval_suite: Suite,
    pub routing_policy: CapabilityRoutingPolicy,
    pub rationale: String,
    pub status: String,
    pub proposed_by: String,
    pub created: i64,
}

/// Author one proposal per recurring `(namespace, task_class)` group.
///
/// Only terminal observations count toward recurrence. Action permissions are derived solely from
/// successful observations and intersected with `known_action_types`, so an untrusted observation
/// cannot invent a permission. The function has no persistence or launch side effects.
pub fn author_capability_proposals(
    observations: &[CapabilityObservation],
    known_action_types: &[String],
    preferred_models: &BTreeMap<(String, String), String>,
    proposed_by: &str,
    now: i64,
) -> Vec<CapabilityProposal> {
    let known: HashSet<&str> = known_action_types.iter().map(String::as_str).collect();
    let normalized_models: BTreeMap<(String, String), &String> = preferred_models
        .iter()
        .map(|((namespace, task_class), model)| {
            (
                (
                    namespace.trim().to_string(),
                    normalize_task_class(task_class),
                ),
                model,
            )
        })
        .collect();
    let mut groups: BTreeMap<(String, String), HashMap<String, &CapabilityObservation>> =
        BTreeMap::new();

    for observation in observations {
        let namespace = observation.task.namespace.trim();
        let task_class = normalize_task_class(&observation.task_class);
        if namespace.is_empty() || task_class.is_empty() || !is_terminal(&observation.task.status) {
            continue;
        }
        groups
            .entry((namespace.to_string(), task_class))
            .or_default()
            .entry(observation.task.id.clone())
            .and_modify(|current| {
                if observation.task.created > current.task.created {
                    *current = observation;
                }
            })
            .or_insert(observation);
    }

    groups
        .into_iter()
        .filter_map(|((namespace, task_class), group)| {
            let mut group: Vec<_> = group.into_values().collect();
            if group.len() < MIN_RECURRING_TASKS {
                return None;
            }
            group.sort_by(|left, right| {
                left.task
                    .created
                    .cmp(&right.task.created)
                    .then_with(|| left.task.id.cmp(&right.task.id))
            });

            let successful = group
                .iter()
                .filter(|item| item.task.status == "done")
                .count();
            if successful < MIN_SUCCESSFUL_TASKS {
                return None;
            }
            let tasks: Vec<TaskRecord> = group
                .iter()
                .map(|item| {
                    let mut task = item.task.clone();
                    task.namespace = namespace.clone();
                    task
                })
                .collect();
            let template = evolve::generate_templates(&tasks).into_iter().next()?;
            let action_types: BTreeSet<String> = group
                .iter()
                .filter(|item| item.task.status == "done")
                .flat_map(|item| item.action_types.iter())
                .filter(|action| known.contains(action.as_str()))
                .cloned()
                .collect();
            let task_class_slug = slug(&task_class);
            let namespace_slug = slug(&namespace);
            let key_hash = group_key_hash(&namespace, &task_class);
            let suite_id = format!("capability-eval-{key_hash}");
            let successful_group: Vec<_> = group
                .iter()
                .filter(|item| item.task.status == "done")
                .collect();
            let case_start = successful_group.len().saturating_sub(MAX_SEED_EVAL_CASES);
            let cases = successful_group
                .into_iter()
                .skip(case_start)
                .enumerate()
                .map(|(index, item)| Case {
                    id: format!("{suite_id}-case-{index}"),
                    name: format!("historical example {}", item.task.id),
                    namespace: namespace.clone(),
                    spec: item.task.spec.clone(),
                    assertions: vec![Assertion {
                        assert_type: "status".to_string(),
                        value: "ok".to_string(),
                    }],
                })
                .collect();

            Some(CapabilityProposal {
                id: format!("capability-proposal-{key_hash}-{now}"),
                namespace: namespace.clone(),
                task_class: task_class.clone(),
                agent_spec: AgentSpec {
                    name: format!("{namespace_slug}-{task_class_slug}-{key_hash}"),
                    namespace: namespace.clone(),
                    task_class: task_class.clone(),
                    instructions: template.content,
                },
                allowed_action_types: action_types.into_iter().collect(),
                eval_suite: Suite {
                    id: suite_id,
                    name: format!("{namespace} {task_class} capability gate"),
                    description: format!(
                        "Seed gate authored from {} recurring terminal task observations",
                        group.len()
                    ),
                    cases,
                },
                routing_policy: CapabilityRoutingPolicy {
                    task_class: task_class.clone(),
                    preferred_model: normalized_models
                        .get(&(namespace.clone(), task_class.clone()))
                        .map(|model| (*model).clone())
                        .unwrap_or_default(),
                    fallback_tier: "capable".to_string(),
                },
                rationale: format!(
                    "recurring task class observed {} times in namespace {namespace}; \
                     {successful}/{} terminal tasks succeeded",
                    group.len(),
                    group.len()
                ),
                status: PROPOSAL_AWAITING_REVIEW.to_string(),
                proposed_by: proposed_by.to_string(),
                created: now,
            })
        })
        .collect()
}

fn normalize_task_class(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .to_ascii_lowercase()
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn group_key_hash(namespace: &str, task_class: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace.len().to_be_bytes());
    hasher.update(namespace.as_bytes());
    hasher.update(task_class.len().to_be_bytes());
    hasher.update(task_class.as_bytes());
    hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_terminal(status: &str) -> bool {
    matches!(status, "done" | "failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        id: &str,
        task_class: &str,
        status: &str,
        action_types: &[&str],
        created: i64,
    ) -> CapabilityObservation {
        CapabilityObservation {
            task: TaskRecord {
                id: id.to_string(),
                spec: format!("Review and repair change {id} with focused verification"),
                status: status.to_string(),
                namespace: "acme".to_string(),
                tokens_used: 100,
                original_spec: None,
                created,
            },
            task_class: task_class.to_string(),
            action_types: action_types.iter().map(|value| value.to_string()).collect(),
        }
    }

    #[test]
    fn authors_complete_review_only_proposal_for_recurring_class() {
        let observations = vec![
            observation("1", "Code Review", "done", &["comment", "invented"], 1),
            observation("2", "code   review", "done", &["invented"], 2),
            observation("3", "code review", "done", &["comment"], 3),
        ];
        let models = BTreeMap::from([(
            (" acme ".to_string(), "Code Review".to_string()),
            "claude-opus-4-8".to_string(),
        )]);

        let proposals = author_capability_proposals(
            &observations,
            &["comment".to_string(), "delete_object".to_string()],
            &models,
            "chisei.author",
            42,
        );

        assert_eq!(proposals.len(), 1);
        let proposal = &proposals[0];
        assert_eq!(proposal.status, PROPOSAL_AWAITING_REVIEW);
        assert_eq!(proposal.allowed_action_types, vec!["comment"]);
        assert_eq!(proposal.eval_suite.cases.len(), 3);
        assert_eq!(proposal.routing_policy.preferred_model, "claude-opus-4-8");
        assert_eq!(proposal.routing_policy.fallback_tier, "capable");
    }

    #[test]
    fn ignores_non_terminal_and_non_recurring_groups() {
        let observations = vec![
            observation("1", "deploy", "done", &[], 1),
            observation("2", "deploy", "planned", &[], 2),
            observation("3", "deploy", "running", &[], 3),
        ];

        assert!(
            author_capability_proposals(&observations, &[], &BTreeMap::new(), "author", 42)
                .is_empty()
        );
    }

    #[test]
    fn duplicate_task_observations_do_not_satisfy_recurrence() {
        let repeated = observation("same-task", "deploy", "done", &[], 1);
        let observations = vec![repeated.clone(), repeated.clone(), repeated];

        assert!(
            author_capability_proposals(&observations, &[], &BTreeMap::new(), "author", 42)
                .is_empty()
        );
    }

    #[test]
    fn requires_two_successful_examples() {
        let observations = vec![
            observation("1", "deploy", "done", &[], 1),
            observation("2", "deploy", "failed", &[], 2),
            observation("3", "deploy", "failed", &[], 3),
        ];

        assert!(
            author_capability_proposals(&observations, &[], &BTreeMap::new(), "author", 42)
                .is_empty()
        );
    }

    #[test]
    fn normalizes_namespace_before_template_generation() {
        let mut observations = vec![
            observation("1", "deploy", "done", &[], 1),
            observation("2", "deploy", "done", &[], 2),
            observation("3", "deploy", "failed", &[], 3),
        ];
        observations[1].task.namespace = " acme ".to_string();

        let proposals =
            author_capability_proposals(&observations, &[], &BTreeMap::new(), "author", 42);

        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].namespace, "acme");
    }

    #[test]
    fn group_ids_are_unambiguous() {
        let mut observations = vec![
            observation("1", "review", "done", &[], 1),
            observation("2", "review", "done", &[], 2),
            observation("3", "review", "done", &[], 3),
            observation("4", "a review", "done", &[], 4),
            observation("5", "a review", "done", &[], 5),
            observation("6", "a review", "done", &[], 6),
        ];
        for observation in &mut observations[..3] {
            observation.task.namespace = "team-a".to_string();
        }
        for observation in &mut observations[3..] {
            observation.task.namespace = "team".to_string();
        }

        let proposals =
            author_capability_proposals(&observations, &[], &BTreeMap::new(), "author", 42);

        assert_eq!(proposals.len(), 2);
        assert_ne!(proposals[0].id, proposals[1].id);
        assert_ne!(proposals[0].eval_suite.id, proposals[1].eval_suite.id);
    }

    #[test]
    fn group_ids_resist_embedded_nul_ambiguity() {
        assert_ne!(group_key_hash("a\0b", "c"), group_key_hash("a", "b\0c"));
    }

    #[test]
    fn seed_suite_is_bounded_to_recent_observations() {
        let observations: Vec<_> = (0..12)
            .map(|index| observation(&index.to_string(), "review", "done", &[], index))
            .collect();

        let proposals =
            author_capability_proposals(&observations, &[], &BTreeMap::new(), "author", 42);

        let cases = &proposals[0].eval_suite.cases;
        assert_eq!(cases.len(), MAX_SEED_EVAL_CASES);
        assert!(cases.first().unwrap().name.ends_with('4'));
        assert!(cases.last().unwrap().name.ends_with("11"));
    }

    #[test]
    fn seed_suite_excludes_failed_observations() {
        let observations = vec![
            observation("1", "review", "done", &[], 1),
            observation("2", "review", "failed", &[], 2),
            observation("3", "review", "done", &[], 3),
        ];

        let proposals =
            author_capability_proposals(&observations, &[], &BTreeMap::new(), "author", 42);
        let cases = &proposals[0].eval_suite.cases;

        assert_eq!(cases.len(), 2);
        assert!(cases.iter().all(|case| !case.name.ends_with('2')));
    }
}
