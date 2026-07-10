//! Governed capability authoring.
//!
//! A capability proposal groups an agent spec, its action allowlist, a seed eval suite, and a
//! routing policy. Authoring is deliberately side-effect free: proposals are review artifacts,
//! not registered agents or live routing changes.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chisei::eval::{Assertion, Case, EvalStore, Suite};
use crate::chisei::evolve::{self, TaskRecord};
use crate::db::sekai::SekaiDb;
use crate::domain::{KIND_CAPABILITY, Link, ListFilter, Object, REL_DEPENDS_ON};
use crate::sekai::audit::{Decision, insert_object_changes, object_diff_changes};

pub const MIN_RECURRING_TASKS: usize = 3;
pub const MIN_SUCCESSFUL_TASKS: usize = 2;
pub const MAX_SEED_EVAL_CASES: usize = 8;

pub const PROPOSAL_AWAITING_REVIEW: &str = "awaiting_review";
pub const PROPOSAL_APPROVED: &str = "approved";
pub const PROPOSAL_REJECTED: &str = "rejected";
pub const PROPOSAL_GATE_PASSED: &str = "gate_passed";
pub const PROPOSAL_GATE_FAILED: &str = "gate_failed";
pub const CAPABILITY_ACTIVE: &str = "active";
pub const CAPABILITY_SUPERSEDED: &str = "superseded";
pub const CAPABILITY_REVOKED: &str = "revoked";

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
    #[serde(default)]
    pub review: Option<CapabilityReview>,
    #[serde(default)]
    pub gate: Option<CapabilityGateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReview {
    pub reviewer: String,
    pub approved: bool,
    pub reason: String,
    pub proposal_digest: String,
    pub reviewed: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGateEvidence {
    pub run_id: String,
    pub passed: bool,
    pub reason: String,
    pub proposal_digest: String,
    pub gated_by: String,
    pub gated: i64,
}

/// Proof that a reviewed, unchanged proposal passed its own eval suite. The registry accepts this
/// authorization rather than a bare status string, preventing an ungated proposal from launching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLaunchAuthorization {
    pub proposal_id: String,
    pub proposal_digest: String,
    pub eval_suite_id: String,
    pub eval_run_id: String,
    pub approved_by: String,
    pub gated_by: String,
    pub authorized: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityGateError {
    InvalidState(String),
    InvalidReviewer(String),
    MissingRun(String),
    WrongSuite { expected: String, actual: String },
    WrongConfig { expected: String, actual: String },
    ProposalChanged,
    Audit(String),
}

impl std::fmt::Display for CapabilityGateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState(state) => write!(formatter, "invalid proposal state: {state}"),
            Self::InvalidReviewer(reason) => write!(formatter, "invalid reviewer: {reason}"),
            Self::MissingRun(run_id) => write!(formatter, "eval run not found: {run_id}"),
            Self::WrongSuite { expected, actual } => {
                write!(
                    formatter,
                    "eval run belongs to suite {actual}, expected {expected}"
                )
            }
            Self::WrongConfig { expected, actual } => {
                write!(
                    formatter,
                    "eval run targets config {actual}, expected {expected}"
                )
            }
            Self::ProposalChanged => write!(formatter, "proposal changed after approval"),
            Self::Audit(error) => write!(formatter, "audit failed: {error}"),
        }
    }
}

impl std::error::Error for CapabilityGateError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityVersion {
    pub id: String,
    pub namespace: String,
    pub task_class: String,
    pub version: u32,
    pub status: String,
    pub proposal: CapabilityProposal,
    pub authorization: CapabilityLaunchAuthorization,
    pub created_by: String,
    pub created: i64,
    pub revoked_by: String,
    pub revoked_reason: String,
    pub revoked: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityRegistryError {
    InvalidAuthorization(String),
    InvalidState(String),
    NotFound(String),
    Storage(String),
}

impl std::fmt::Display for CapabilityRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAuthorization(reason) => {
                write!(formatter, "invalid launch authorization: {reason}")
            }
            Self::InvalidState(state) => write!(formatter, "invalid capability state: {state}"),
            Self::NotFound(id) => write!(formatter, "capability not found: {id}"),
            Self::Storage(error) => {
                write!(formatter, "capability registry storage failed: {error}")
            }
        }
    }
}

impl std::error::Error for CapabilityRegistryError {}

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
                review: None,
                gate: None,
            })
        })
        .collect()
}

/// Record a human approval or rejection of the exact proposal contents.
pub fn review_capability_proposal(
    db: &SekaiDb,
    proposal: &mut CapabilityProposal,
    reviewer: &str,
    approved: bool,
    reason: &str,
    now: i64,
) -> Result<(), CapabilityGateError> {
    if proposal.status != PROPOSAL_AWAITING_REVIEW {
        return Err(CapabilityGateError::InvalidState(proposal.status.clone()));
    }
    let reviewer = reviewer.trim();
    if reviewer.is_empty() {
        return Err(CapabilityGateError::InvalidReviewer(
            "reviewer is required".to_string(),
        ));
    }
    if reviewer == proposal.proposed_by.trim() {
        return Err(CapabilityGateError::InvalidReviewer(
            "proposer cannot approve or reject their own proposal".to_string(),
        ));
    }

    let digest = proposal_digest(proposal);
    let status = if approved {
        PROPOSAL_APPROVED
    } else {
        PROPOSAL_REJECTED
    };
    record_capability_decision(
        db,
        proposal,
        reviewer,
        "capability_proposal_reviewed",
        reason,
        status,
        BTreeMap::from([
            ("approved".to_string(), approved.to_string()),
            ("proposal_digest".to_string(), digest.clone()),
        ]),
        now,
    )?;

    proposal.status = status.to_string();
    proposal.review = Some(CapabilityReview {
        reviewer: reviewer.to_string(),
        approved,
        reason: reason.to_string(),
        proposal_digest: digest,
        reviewed: now,
    });
    Ok(())
}

/// Gate an approved proposal against one run of its own seed suite.
///
/// Every expected case must appear exactly once and pass. The proposal digest must still match the
/// human-reviewed digest. Failed evals are terminally recorded as `gate_failed`; infrastructure or
/// caller errors leave the approved proposal untouched so a valid run can be supplied later.
pub fn gate_capability_proposal(
    db: &SekaiDb,
    eval: &EvalStore,
    proposal: &mut CapabilityProposal,
    run_id: &str,
    gated_by: &str,
    now: i64,
) -> Result<Option<CapabilityLaunchAuthorization>, CapabilityGateError> {
    if proposal.status != PROPOSAL_APPROVED {
        return Err(CapabilityGateError::InvalidState(proposal.status.clone()));
    }
    let review = proposal
        .review
        .as_ref()
        .filter(|review| review.approved)
        .ok_or_else(|| {
            CapabilityGateError::InvalidState("approval evidence missing".to_string())
        })?;
    let current_digest = proposal_digest(proposal);
    if review.proposal_digest != current_digest {
        return Err(CapabilityGateError::ProposalChanged);
    }
    let run = eval
        .get_run(run_id)
        .ok_or_else(|| CapabilityGateError::MissingRun(run_id.to_string()))?;
    if run.suite_id != proposal.eval_suite.id {
        return Err(CapabilityGateError::WrongSuite {
            expected: proposal.eval_suite.id.clone(),
            actual: run.suite_id,
        });
    }
    if run.config_ref != proposal.id {
        return Err(CapabilityGateError::WrongConfig {
            expected: proposal.id.clone(),
            actual: run.config_ref,
        });
    }

    let mut result_counts: HashMap<&str, usize> = HashMap::new();
    let mut failed_cases = Vec::new();
    for result in &run.results {
        *result_counts.entry(&result.case_id).or_default() += 1;
        if !result.passed {
            failed_cases.push(result.case_id.clone());
        }
    }
    let invalid_cases: Vec<String> = proposal
        .eval_suite
        .cases
        .iter()
        .filter(|case| result_counts.get(case.id.as_str()).copied() != Some(1))
        .map(|case| case.id.clone())
        .collect();
    let passed = invalid_cases.is_empty()
        && failed_cases.is_empty()
        && run.results.len() == proposal.eval_suite.cases.len();
    let reason = if passed {
        format!("all {} seed eval cases passed", run.results.len())
    } else {
        format!(
            "capability eval failed; invalid case coverage: [{}]; failed cases: [{}]",
            invalid_cases.join(", "),
            failed_cases.join(", ")
        )
    };
    let status = if passed {
        PROPOSAL_GATE_PASSED
    } else {
        PROPOSAL_GATE_FAILED
    };
    record_capability_decision(
        db,
        proposal,
        gated_by,
        "capability_eval_gated",
        &reason,
        status,
        BTreeMap::from([
            ("eval_run_id".to_string(), run.id.clone()),
            ("eval_suite_id".to_string(), run.suite_id.clone()),
            ("proposal_digest".to_string(), current_digest.clone()),
        ]),
        now,
    )?;

    proposal.status = status.to_string();
    proposal.gate = Some(CapabilityGateEvidence {
        run_id: run.id.clone(),
        passed,
        reason,
        proposal_digest: current_digest.clone(),
        gated_by: gated_by.to_string(),
        gated: now,
    });
    if !passed {
        return Ok(None);
    }

    Ok(Some(CapabilityLaunchAuthorization {
        proposal_id: proposal.id.clone(),
        proposal_digest: current_digest,
        eval_suite_id: proposal.eval_suite.id.clone(),
        eval_run_id: run.id,
        approved_by: review.reviewer.clone(),
        gated_by: gated_by.to_string(),
        authorized: now,
    }))
}

/// Register a new active capability version from a valid launch authorization.
///
/// Version creation, superseding the prior active version, lineage-link creation, object-change
/// audit, and decision audit share one SQLite transaction. This guarantees at most one active
/// version per `(namespace, task_class)` even under concurrent callers.
pub fn register_capability(
    db: &SekaiDb,
    proposal: &CapabilityProposal,
    authorization: &CapabilityLaunchAuthorization,
    actor: &str,
    now: i64,
) -> Result<CapabilityVersion, CapabilityRegistryError> {
    validate_launch_authorization(proposal, authorization)?;
    let actor = actor.trim();
    if actor.is_empty() {
        return Err(CapabilityRegistryError::InvalidAuthorization(
            "registering actor is required".to_string(),
        ));
    }
    let namespace = proposal.namespace.trim().to_string();
    let task_class = normalize_task_class(&proposal.task_class);
    if namespace.is_empty() || task_class.is_empty() {
        return Err(CapabilityRegistryError::InvalidAuthorization(
            "namespace and task class are required".to_string(),
        ));
    }

    let mut conn = db.conn();
    let tx = conn.transaction().map_err(registry_storage)?;
    let mut existing = {
        let mut statement = tx
            .prepare(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated \
                 FROM sekai_objects WHERE kind = ?1 AND namespace = ?2 \
                 AND json_extract(properties, '$.task_class') = ?3",
            )
            .map_err(registry_storage)?;
        let rows = statement
            .query_map(
                params![KIND_CAPABILITY, namespace, task_class],
                crate::db::sekai::row_to_object,
            )
            .map_err(registry_storage)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(registry_storage)?
    };
    existing.sort_by_key(capability_object_version);
    let version = existing
        .iter()
        .map(capability_object_version)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| CapabilityRegistryError::InvalidState("version overflow".to_string()))?;
    let previous = existing.last().cloned();
    let mut changes = Vec::new();

    for object in existing.iter_mut().filter(|object| {
        object.properties.get("status").map(String::as_str) == Some(CAPABILITY_ACTIVE)
    }) {
        let before = object.clone();
        object
            .properties
            .insert("status".to_string(), CAPABILITY_SUPERSEDED.to_string());
        object.updated = now;
        let properties = serde_json::to_string(&object.properties).map_err(registry_storage)?;
        tx.execute(
            "UPDATE sekai_objects SET properties = ?2, updated = ?3 WHERE id = ?1",
            params![object.id, properties, now],
        )
        .map_err(registry_storage)?;
        changes.extend(object_diff_changes(actor, Some(&before), Some(object), now));
    }

    let capability = CapabilityVersion {
        id: format!(
            "capability-{}-v{version}",
            group_key_hash(&namespace, &task_class)
        ),
        namespace,
        task_class,
        version,
        status: CAPABILITY_ACTIVE.to_string(),
        proposal: proposal.clone(),
        authorization: authorization.clone(),
        created_by: actor.to_string(),
        created: now,
        revoked_by: String::new(),
        revoked_reason: String::new(),
        revoked: 0,
    };
    let object = capability_to_object(&capability)?;
    let properties = serde_json::to_string(&object.properties).map_err(registry_storage)?;
    tx.execute(
        "INSERT INTO sekai_objects \
         (id, kind, name, namespace, external_id, properties, created, updated) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            object.id,
            object.kind,
            object.name,
            object.namespace,
            object.external_id,
            properties,
            object.created,
            object.updated,
        ],
    )
    .map_err(registry_storage)?;
    changes.extend(object_diff_changes(actor, None, Some(&object), now));

    if let Some(previous) = previous {
        let link = Link {
            id: format!("capability-lineage-{}", capability.id),
            from_id: capability.id.clone(),
            to_id: previous.id,
            relation: REL_DEPENDS_ON.to_string(),
            created: now,
        };
        tx.execute(
            "INSERT INTO sekai_links (id, from_id, to_id, relation, created) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                link.id,
                link.from_id,
                link.to_id,
                link.relation,
                link.created
            ],
        )
        .map_err(registry_storage)?;
    }
    insert_object_changes(&tx, &changes).map_err(registry_storage)?;
    insert_registry_decision(
        &tx,
        &capability.id,
        actor,
        "capability_registered",
        "approved capability passed its seed eval suite",
        CAPABILITY_ACTIVE,
        BTreeMap::from([
            ("proposal_id".to_string(), proposal.id.clone()),
            (
                "proposal_digest".to_string(),
                authorization.proposal_digest.clone(),
            ),
            ("version".to_string(), version.to_string()),
        ]),
        now,
    )?;
    tx.commit().map_err(registry_storage)?;
    Ok(capability)
}

/// Revoke an active capability version without deleting its graph or audit history.
pub fn revoke_capability(
    db: &SekaiDb,
    capability_id: &str,
    actor: &str,
    reason: &str,
    now: i64,
) -> Result<CapabilityVersion, CapabilityRegistryError> {
    let actor = actor.trim();
    if actor.is_empty() || reason.trim().is_empty() {
        return Err(CapabilityRegistryError::InvalidState(
            "revocation actor and reason are required".to_string(),
        ));
    }
    let mut conn = db.conn();
    let tx = conn.transaction().map_err(registry_storage)?;
    let before = tx
        .query_row(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated \
             FROM sekai_objects WHERE id = ?1",
            params![capability_id],
            crate::db::sekai::row_to_object,
        )
        .optional()
        .map_err(registry_storage)?
        .ok_or_else(|| CapabilityRegistryError::NotFound(capability_id.to_string()))?;
    if before.kind != KIND_CAPABILITY {
        return Err(CapabilityRegistryError::NotFound(capability_id.to_string()));
    }
    let mut capability = capability_from_object(&before)?;
    if capability.status != CAPABILITY_ACTIVE {
        return Err(CapabilityRegistryError::InvalidState(
            capability.status.clone(),
        ));
    }
    capability.status = CAPABILITY_REVOKED.to_string();
    capability.revoked_by = actor.to_string();
    capability.revoked_reason = reason.trim().to_string();
    capability.revoked = now;
    let after = capability_to_object(&capability)?;
    let properties = serde_json::to_string(&after.properties).map_err(registry_storage)?;
    tx.execute(
        "UPDATE sekai_objects SET properties = ?2, updated = ?3 WHERE id = ?1",
        params![after.id, properties, now],
    )
    .map_err(registry_storage)?;
    let changes = object_diff_changes(actor, Some(&before), Some(&after), now);
    insert_object_changes(&tx, &changes).map_err(registry_storage)?;
    insert_registry_decision(
        &tx,
        capability_id,
        actor,
        "capability_revoked",
        reason,
        CAPABILITY_REVOKED,
        BTreeMap::from([("version".to_string(), capability.version.to_string())]),
        now,
    )?;
    tx.commit().map_err(registry_storage)?;
    Ok(capability)
}

pub fn list_capability_versions(
    db: &SekaiDb,
    namespace: &str,
    task_class: &str,
) -> Result<Vec<CapabilityVersion>, CapabilityRegistryError> {
    let normalized_class = normalize_task_class(task_class);
    let mut capabilities: Vec<_> = db
        .list_all_objects(&ListFilter {
            kind: Some(KIND_CAPABILITY.to_string()),
            namespace: Some(namespace.trim().to_string()),
            ..Default::default()
        })
        .map_err(registry_storage)?
        .into_iter()
        .filter(|object| {
            object.properties.get("task_class").map(String::as_str)
                == Some(normalized_class.as_str())
        })
        .map(|object| capability_from_object(&object))
        .collect::<Result<_, _>>()?;
    capabilities.sort_by_key(|capability| capability.version);
    Ok(capabilities)
}

pub fn get_active_capability(
    db: &SekaiDb,
    namespace: &str,
    task_class: &str,
) -> Result<Option<CapabilityVersion>, CapabilityRegistryError> {
    let active: Vec<_> = list_capability_versions(db, namespace, task_class)?
        .into_iter()
        .filter(|capability| capability.status == CAPABILITY_ACTIVE)
        .collect();
    match active.len() {
        0 => Ok(None),
        1 => Ok(active.into_iter().next()),
        count => Err(CapabilityRegistryError::InvalidState(format!(
            "{count} active versions found"
        ))),
    }
}

fn validate_launch_authorization(
    proposal: &CapabilityProposal,
    authorization: &CapabilityLaunchAuthorization,
) -> Result<(), CapabilityRegistryError> {
    let gate = proposal
        .gate
        .as_ref()
        .filter(|gate| gate.passed)
        .ok_or_else(|| {
            CapabilityRegistryError::InvalidAuthorization(
                "passing gate evidence is required".to_string(),
            )
        })?;
    let digest = proposal_digest(proposal);
    let valid = proposal.status == PROPOSAL_GATE_PASSED
        && authorization.proposal_id == proposal.id
        && authorization.proposal_digest == digest
        && authorization.proposal_digest == gate.proposal_digest
        && authorization.eval_suite_id == proposal.eval_suite.id
        && authorization.eval_run_id == gate.run_id
        && authorization.approved_by
            == proposal
                .review
                .as_ref()
                .filter(|review| review.approved)
                .map(|review| review.reviewer.as_str())
                .unwrap_or_default()
        && authorization.gated_by == gate.gated_by;
    if !valid {
        return Err(CapabilityRegistryError::InvalidAuthorization(
            "authorization does not match the reviewed and gated proposal".to_string(),
        ));
    }
    Ok(())
}

fn capability_to_object(capability: &CapabilityVersion) -> Result<Object, CapabilityRegistryError> {
    let mut properties = HashMap::new();
    properties.insert("task_class".to_string(), capability.task_class.clone());
    properties.insert("version".to_string(), capability.version.to_string());
    properties.insert("status".to_string(), capability.status.clone());
    properties.insert(
        "proposal".to_string(),
        serde_json::to_string(&capability.proposal).map_err(registry_storage)?,
    );
    properties.insert(
        "authorization".to_string(),
        serde_json::to_string(&capability.authorization).map_err(registry_storage)?,
    );
    properties.insert("created_by".to_string(), capability.created_by.clone());
    properties.insert("revoked_by".to_string(), capability.revoked_by.clone());
    properties.insert(
        "revoked_reason".to_string(),
        capability.revoked_reason.clone(),
    );
    properties.insert("revoked".to_string(), capability.revoked.to_string());
    Ok(Object {
        id: capability.id.clone(),
        kind: KIND_CAPABILITY.to_string(),
        name: capability.proposal.agent_spec.name.clone(),
        namespace: capability.namespace.clone(),
        external_id: format!(
            "capability:{}:v{}",
            group_key_hash(&capability.namespace, &capability.task_class),
            capability.version
        ),
        properties,
        created: capability.created,
        updated: capability.revoked.max(capability.created),
    })
}

fn capability_from_object(object: &Object) -> Result<CapabilityVersion, CapabilityRegistryError> {
    let property = |name: &str| {
        object.properties.get(name).cloned().ok_or_else(|| {
            CapabilityRegistryError::Storage(format!(
                "capability {} is missing property {name}",
                object.id
            ))
        })
    };
    Ok(CapabilityVersion {
        id: object.id.clone(),
        namespace: object.namespace.clone(),
        task_class: property("task_class")?,
        version: property("version")?
            .parse()
            .map_err(|error| registry_storage(format!("invalid version: {error}")))?,
        status: property("status")?,
        proposal: serde_json::from_str(&property("proposal")?).map_err(registry_storage)?,
        authorization: serde_json::from_str(&property("authorization")?)
            .map_err(registry_storage)?,
        created_by: property("created_by")?,
        created: object.created,
        revoked_by: property("revoked_by")?,
        revoked_reason: property("revoked_reason")?,
        revoked: property("revoked")?
            .parse()
            .map_err(|error| registry_storage(format!("invalid revoked timestamp: {error}")))?,
    })
}

fn capability_object_version(object: &Object) -> u32 {
    object
        .properties
        .get("version")
        .and_then(|version| version.parse().ok())
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn insert_registry_decision(
    conn: &rusqlite::Connection,
    target_id: &str,
    actor: &str,
    action: &str,
    reason: &str,
    outcome: &str,
    evidence: BTreeMap<String, String>,
    now: i64,
) -> Result<(), CapabilityRegistryError> {
    let evidence = serde_json::to_string(&evidence).map_err(registry_storage)?;
    conn.execute(
        "INSERT INTO sekai_decisions \
         (id, timestamp, actor, action, reason, evidence, target_id, outcome) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            uuid::Uuid::new_v4().to_string(),
            now,
            actor,
            action,
            reason,
            evidence,
            target_id,
            outcome,
        ],
    )
    .map_err(registry_storage)?;
    Ok(())
}

fn registry_storage(error: impl std::fmt::Display) -> CapabilityRegistryError {
    CapabilityRegistryError::Storage(error.to_string())
}

fn proposal_digest(proposal: &CapabilityProposal) -> String {
    let canonical = serde_json::to_vec(&(
        &proposal.id,
        &proposal.namespace,
        &proposal.task_class,
        &proposal.agent_spec,
        &proposal.allowed_action_types,
        &proposal.eval_suite,
        &proposal.routing_policy,
        &proposal.proposed_by,
        proposal.created,
    ))
    .expect("capability proposal fields are serializable");
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn record_capability_decision(
    db: &SekaiDb,
    proposal: &CapabilityProposal,
    actor: &str,
    action: &str,
    reason: &str,
    outcome: &str,
    evidence: BTreeMap<String, String>,
    now: i64,
) -> Result<(), CapabilityGateError> {
    db.record_decision(&Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: now,
        actor: actor.to_string(),
        action: action.to_string(),
        reason: reason.to_string(),
        evidence: evidence.into_iter().collect(),
        target_id: proposal.id.clone(),
        outcome: outcome.to_string(),
    })
    .map_err(CapabilityGateError::Audit)
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
    use crate::chisei::eval::{CaseResult, Run};
    use crate::sekai::audit::DecisionFilter;

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

    fn proposal_at(now: i64) -> CapabilityProposal {
        let observations = vec![
            observation("1", "review", "done", &["comment"], 1),
            observation("2", "review", "done", &["comment"], 2),
            observation("3", "review", "done", &["comment"], 3),
        ];
        author_capability_proposals(
            &observations,
            &["comment".to_string()],
            &BTreeMap::new(),
            "chisei.author",
            now,
        )
        .remove(0)
    }

    fn proposal() -> CapabilityProposal {
        proposal_at(42)
    }

    fn authorized_proposal(
        db: &SekaiDb,
        now: i64,
    ) -> (CapabilityProposal, CapabilityLaunchAuthorization) {
        authorize_proposal(db, proposal_at(now), now)
    }

    fn authorize_proposal(
        db: &SekaiDb,
        mut proposal: CapabilityProposal,
        now: i64,
    ) -> (CapabilityProposal, CapabilityLaunchAuthorization) {
        let eval = EvalStore::new();
        review_capability_proposal(
            db,
            &mut proposal,
            "human:reviewer",
            true,
            "approved",
            now + 1,
        )
        .unwrap();
        let mut run = eval_run(&proposal, true);
        run.id = format!("capability-run-{now}");
        eval.create_run(run.clone());
        let authorization =
            gate_capability_proposal(db, &eval, &mut proposal, &run.id, "chisei.gate", now + 2)
                .unwrap()
                .unwrap();
        (proposal, authorization)
    }

    fn eval_run(proposal: &CapabilityProposal, passed: bool) -> Run {
        Run {
            id: "capability-run-1".to_string(),
            suite_id: proposal.eval_suite.id.clone(),
            config_ref: proposal.id.clone(),
            results: proposal
                .eval_suite
                .cases
                .iter()
                .map(|case| CaseResult {
                    case_id: case.id.clone(),
                    passed,
                    status: if passed { "ok" } else { "failed" }.to_string(),
                    result: String::new(),
                    score: if passed { 100 } else { 0 },
                    reason: String::new(),
                    elapsed: 1,
                })
                .collect(),
            timestamp: 100,
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

    #[test]
    fn review_requires_an_independent_reviewer_and_is_audited() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut proposal = proposal();

        assert!(matches!(
            review_capability_proposal(
                &db,
                &mut proposal,
                "chisei.author",
                true,
                "self approval",
                50,
            ),
            Err(CapabilityGateError::InvalidReviewer(_))
        ));
        review_capability_proposal(
            &db,
            &mut proposal,
            "human:reviewer",
            true,
            "scope and eval suite are appropriate",
            51,
        )
        .unwrap();

        assert_eq!(proposal.status, PROPOSAL_APPROVED);
        let decisions = db
            .list_decisions(&DecisionFilter {
                target_id: Some(proposal.id.clone()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].action, "capability_proposal_reviewed");
        assert_eq!(decisions[0].outcome, PROPOSAL_APPROVED);
    }

    #[test]
    fn gate_rejects_a_proposal_changed_after_approval() {
        let db = SekaiDb::new(":memory:").unwrap();
        let eval = EvalStore::new();
        let mut proposal = proposal();
        review_capability_proposal(&db, &mut proposal, "reviewer", true, "approved", 50).unwrap();
        proposal.allowed_action_types.push("new-action".to_string());
        eval.create_run(eval_run(&proposal, true));

        assert_eq!(
            gate_capability_proposal(
                &db,
                &eval,
                &mut proposal,
                "capability-run-1",
                "chisei.gate",
                60,
            ),
            Err(CapabilityGateError::ProposalChanged)
        );
        assert_eq!(proposal.status, PROPOSAL_APPROVED);
    }

    #[test]
    fn gate_rejects_a_run_from_another_proposal() {
        let db = SekaiDb::new(":memory:").unwrap();
        let eval = EvalStore::new();
        let mut proposal = proposal();
        review_capability_proposal(&db, &mut proposal, "reviewer", true, "approved", 50).unwrap();
        let mut run = eval_run(&proposal, true);
        run.config_ref = "older-proposal".to_string();
        eval.create_run(run);
        let expected_id = proposal.id.clone();

        assert_eq!(
            gate_capability_proposal(
                &db,
                &eval,
                &mut proposal,
                "capability-run-1",
                "chisei.gate",
                60,
            ),
            Err(CapabilityGateError::WrongConfig {
                expected: expected_id,
                actual: "older-proposal".to_string(),
            })
        );
        assert_eq!(proposal.status, PROPOSAL_APPROVED);
    }

    #[test]
    fn passing_own_suite_authorizes_launch_and_is_audited() {
        let db = SekaiDb::new(":memory:").unwrap();
        let eval = EvalStore::new();
        let mut proposal = proposal();
        review_capability_proposal(&db, &mut proposal, "reviewer", true, "approved", 50).unwrap();
        eval.create_run(eval_run(&proposal, true));

        let authorization = gate_capability_proposal(
            &db,
            &eval,
            &mut proposal,
            "capability-run-1",
            "chisei.gate",
            60,
        )
        .unwrap()
        .expect("launch authorization");

        assert_eq!(proposal.status, PROPOSAL_GATE_PASSED);
        assert_eq!(authorization.proposal_id, proposal.id);
        assert_eq!(authorization.approved_by, "reviewer");
        let decisions = db
            .list_decisions(&DecisionFilter {
                target_id: Some(proposal.id.clone()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 2);
        assert!(
            decisions
                .iter()
                .any(|decision| decision.action == "capability_eval_gated"
                    && decision.outcome == PROPOSAL_GATE_PASSED)
        );
    }

    #[test]
    fn incomplete_or_failing_suite_is_terminally_gate_failed() {
        let db = SekaiDb::new(":memory:").unwrap();
        let eval = EvalStore::new();
        let mut proposal = proposal();
        review_capability_proposal(&db, &mut proposal, "reviewer", true, "approved", 50).unwrap();
        let mut run = eval_run(&proposal, true);
        run.results.pop();
        eval.create_run(run);

        let authorization = gate_capability_proposal(
            &db,
            &eval,
            &mut proposal,
            "capability-run-1",
            "chisei.gate",
            60,
        )
        .unwrap();

        assert!(authorization.is_none());
        assert_eq!(proposal.status, PROPOSAL_GATE_FAILED);
        assert!(!proposal.gate.as_ref().unwrap().passed);
    }

    #[test]
    fn registry_rejects_forged_launch_authorization() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (proposal, mut authorization) = authorized_proposal(&db, 100);
        authorization.proposal_digest = "forged".to_string();

        assert!(matches!(
            register_capability(&db, &proposal, &authorization, "human:registrar", 200),
            Err(CapabilityRegistryError::InvalidAuthorization(_))
        ));
        assert!(
            list_capability_versions(&db, "acme", "review")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn registry_versions_atomically_and_links_lineage() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (proposal_v1, authorization_v1) = authorized_proposal(&db, 100);
        let version_1 =
            register_capability(&db, &proposal_v1, &authorization_v1, "human:registrar", 200)
                .unwrap();
        let (proposal_v2, authorization_v2) = authorized_proposal(&db, 300);
        let version_2 =
            register_capability(&db, &proposal_v2, &authorization_v2, "human:registrar", 400)
                .unwrap();

        assert_eq!(version_1.version, 1);
        assert_eq!(version_2.version, 2);
        let versions = list_capability_versions(&db, "acme", "Review").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].status, CAPABILITY_SUPERSEDED);
        assert_eq!(versions[1].status, CAPABILITY_ACTIVE);
        assert_eq!(
            get_active_capability(&db, "acme", "review")
                .unwrap()
                .unwrap()
                .id,
            version_2.id
        );
        let lineage = db
            .get_link(&format!("capability-lineage-{}", version_2.id))
            .unwrap()
            .unwrap();
        assert_eq!(lineage.from_id, version_2.id);
        assert_eq!(lineage.to_id, version_1.id);
        assert_eq!(lineage.relation, REL_DEPENDS_ON);
    }

    #[test]
    fn registry_versions_canonical_namespace_and_task_class_keys() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut raw_proposal = proposal_at(100);
        raw_proposal.namespace = " acme ".to_string();
        raw_proposal.task_class = "Code   Review".to_string();
        let (proposal_v1, authorization_v1) = authorize_proposal(&db, raw_proposal, 100);
        let version_1 =
            register_capability(&db, &proposal_v1, &authorization_v1, "human:registrar", 200)
                .unwrap();

        let mut canonical_proposal = proposal_at(300);
        canonical_proposal.task_class = "code_review".to_string();
        let (proposal_v2, authorization_v2) = authorize_proposal(&db, canonical_proposal, 300);
        let version_2 =
            register_capability(&db, &proposal_v2, &authorization_v2, "human:registrar", 400)
                .unwrap();

        assert_eq!(version_1.namespace, "acme");
        assert_eq!(version_1.task_class, "code_review");
        assert_eq!(version_2.version, 2);
        let versions = list_capability_versions(&db, " acme ", "Code Review").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].status, CAPABILITY_SUPERSEDED);
        assert_eq!(versions[1].status, CAPABILITY_ACTIVE);
    }

    #[test]
    fn revocation_preserves_version_and_removes_it_from_active_lookup() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (proposal, authorization) = authorized_proposal(&db, 100);
        let registered =
            register_capability(&db, &proposal, &authorization, "human:registrar", 200).unwrap();

        let revoked = revoke_capability(
            &db,
            &registered.id,
            "human:security",
            "permission scope is obsolete",
            300,
        )
        .unwrap();

        assert_eq!(revoked.status, CAPABILITY_REVOKED);
        assert_eq!(revoked.revoked_by, "human:security");
        assert!(
            get_active_capability(&db, "acme", "review")
                .unwrap()
                .is_none()
        );
        let versions = list_capability_versions(&db, "acme", "review").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].status, CAPABILITY_REVOKED);
        let decisions = db
            .list_decisions(&DecisionFilter {
                target_id: Some(registered.id),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|decision| decision.action == "capability_revoked")
        );
    }
}
