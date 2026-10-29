//! Agent disposition precision (#1990, part of #1670).
//!
//! Every security disposition an agent records is later resolved:
//!
//! - **overturned** when its successor is a reopen for a changed basis fact
//!   (#1925), or a human supersedes it with a different disposition;
//! - **confirmed** when a human supersedes it with the same disposition, it
//!   reopens only because its own expiry passed, or it stands unsuperseded
//!   for the settle period;
//! - **pending** otherwise, which includes a disposition another agent
//!   superseded: that is no human judgement of it.
//!
//! Precision is confirmed over resolved, counted per recorder, recorder
//! revision and finding class, for dispositions recorded inside the trailing
//! window. Below the minimum resolved count a group reads `incomplete` and
//! carries no rate, so too little evidence is never read as good evidence.
//! The recorder is the stamped `recorded_by`, and whether it was an agent is
//! the stamped `recorder_kind`, so retiring a service principal later does
//! not rewrite its history. A disposition without them, or a `needs-review`
//! disposition, is no agent's decision and is not counted.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use sha2::Digest as _;

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, Object};
use crate::sekai::security_package::{
    DISPOSITION_NEEDS_REVIEW, FACT_EXPIRES_AT, KIND_DISPOSITION, PROPERTY_FINDING_CLASS,
    PROPERTY_RECORDED_BY, PROPERTY_RECORDER_KIND, PROPERTY_RECORDER_REVISION, RECORDER_AGENT,
    RECORDER_HUMAN, UNCLASSIFIED,
};

pub const STATUS_MEASURED: &str = "measured";
pub const STATUS_INCOMPLETE: &str = "incomplete";

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const PAGE: i32 = 500;

/// Which dispositions count and when a group is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecisionWindow {
    /// Dispositions recorded within this long before now count.
    pub window_ms: i64,
    /// An unsuperseded disposition is confirmed once it is this old.
    pub settle_ms: i64,
    /// Fewer resolved dispositions than this read `incomplete`.
    pub min_resolved: u32,
}

impl PrecisionWindow {
    /// Ninety days of history, confirmed after fourteen days unchallenged,
    /// measured from twenty resolved dispositions.
    pub const fn production() -> Self {
        Self {
            window_ms: 90 * DAY_MS,
            settle_ms: 14 * DAY_MS,
            min_resolved: 20,
        }
    }
}

/// One recorder revision's precision on one finding class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispositionPrecision {
    pub recorded_by: String,
    /// Empty for an agent that is not a site agent instance.
    pub recorder_revision: String,
    pub finding_class: String,
    pub confirmed: u32,
    pub overturned: u32,
    pub pending: u32,
    /// [`STATUS_MEASURED`] or [`STATUS_INCOMPLETE`].
    pub status: &'static str,
    /// Confirmed over resolved, in basis points; `None` while incomplete.
    pub precision_bps: Option<u32>,
    /// Overturned over resolved, in basis points; `None` while incomplete.
    pub overturn_bps: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Confirmed,
    Overturned,
    Pending,
}

/// The precision of every agent recorder in `namespace` as of `now_ms`,
/// sorted by recorder, revision and class.
pub fn disposition_precision(
    db: &RuntimeDb,
    namespace: &str,
    window: PrecisionWindow,
    now_ms: i64,
) -> Result<Vec<DispositionPrecision>, String> {
    let dispositions = all_dispositions(db, namespace)?;
    // As of `now_ms`: a later supersede has not happened yet.
    let successors: HashMap<&str, &Object> = dispositions
        .iter()
        .filter(|object| object.created <= now_ms)
        .filter_map(|object| property(object, "supersedes").map(|previous| (previous, object)))
        .collect();
    let mut classes = HashMap::new();
    let mut groups: BTreeMap<(String, String, String), [u32; 3]> = BTreeMap::new();
    for disposition in &dispositions {
        let Some(recorder) = property(disposition, PROPERTY_RECORDED_BY) else {
            continue;
        };
        if property(disposition, "disposition") == Some(DISPOSITION_NEEDS_REVIEW)
            || disposition.created <= now_ms.saturating_sub(window.window_ms)
            || disposition.created > now_ms
            || !is_agent(disposition)
        {
            continue;
        }
        let resolution = match successors.get(disposition.id.as_str()) {
            Some(successor) => resolve(disposition, successor),
            None if disposition.created <= now_ms.saturating_sub(window.settle_ms) => {
                Resolution::Confirmed
            }
            None => Resolution::Pending,
        };
        let exposure = property(disposition, "exposure_id").unwrap_or_default();
        let class = match classes.get(exposure) {
            Some(class) => String::clone(class),
            None => {
                let class = finding_class(db, exposure)?;
                classes.insert(exposure.to_string(), class.clone());
                class
            }
        };
        let revision = property(disposition, PROPERTY_RECORDER_REVISION).unwrap_or_default();
        let counts = groups
            .entry((recorder.to_string(), revision.to_string(), class))
            .or_default();
        counts[resolution as usize] += 1;
    }
    Ok(groups
        .into_iter()
        .map(
            |((recorded_by, recorder_revision, finding_class), counts)| {
                let [confirmed, overturned, pending] = counts;
                let resolved = confirmed + overturned;
                let measured = resolved >= window.min_resolved.max(1);
                // In u64: a busy group's count times 10 000 overflows u32. The
                // quotient is at most 10 000.
                let rate = |count: u32| {
                    measured.then(|| (u64::from(count) * 10_000 / u64::from(resolved)) as u32)
                };
                DispositionPrecision {
                    recorded_by,
                    recorder_revision,
                    finding_class,
                    confirmed,
                    overturned,
                    pending,
                    status: if measured {
                        STATUS_MEASURED
                    } else {
                        STATUS_INCOMPLETE
                    },
                    precision_bps: rate(confirmed),
                    overturn_bps: rate(overturned),
                }
            },
        )
        .collect())
}

/// How `successor` resolves `disposition`.
fn resolve(disposition: &Object, successor: &Object) -> Resolution {
    if property(successor, "disposition") == Some(DISPOSITION_NEEDS_REVIEW) {
        return if property(successor, "reopened_fact") == Some(FACT_EXPIRES_AT) {
            Resolution::Confirmed
        } else {
            Resolution::Overturned
        };
    }
    match property(successor, PROPERTY_RECORDER_KIND) {
        Some(RECORDER_HUMAN) => {
            if property(successor, "disposition") == property(disposition, "disposition") {
                Resolution::Confirmed
            } else {
                Resolution::Overturned
            }
        }
        _ => Resolution::Pending,
    }
}

/// The class of the finding behind `exposure_id`.
fn finding_class(db: &RuntimeDb, exposure_id: &str) -> Result<String, String> {
    let finding = match db.get_object(exposure_id)? {
        Some(exposure) => match property(&exposure, "finding_id") {
            Some(finding_id) => db.get_object(finding_id)?,
            None => None,
        },
        None => None,
    };
    Ok(finding
        .as_ref()
        .and_then(|finding| property(finding, PROPERTY_FINDING_CLASS))
        .unwrap_or(UNCLASSIFIED)
        .to_string())
}

/// Every disposition of `namespace`, once each. Offset pages are separate
/// reads, so one committed between them can shift a row into the next page;
/// dispositions are never deleted, so a shift only repeats a row, and keying
/// by id drops the repeat.
fn all_dispositions(db: &RuntimeDb, namespace: &str) -> Result<Vec<Object>, String> {
    let mut all = BTreeMap::new();
    let mut offset = 0usize;
    loop {
        let page = db.list_objects(&ListFilter {
            kind: Some(KIND_DISPOSITION.into()),
            namespace: Some(namespace.into()),
            limit: PAGE,
            offset: i32::try_from(offset).map_err(|error| error.to_string())?,
            ..Default::default()
        })?;
        let done = page.len() < PAGE as usize;
        offset += page.len();
        for object in page {
            all.insert(object.id.clone(), object);
        }
        if done {
            return Ok(all.into_values().collect());
        }
    }
}

/// Classified when it was recorded, never from today's registry.
fn is_agent(disposition: &Object) -> bool {
    property(disposition, PROPERTY_RECORDER_KIND) == Some(RECORDER_AGENT)
}

fn property<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    object
        .properties
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
}

/// The decision ledger action of an autonomy crossing receipt (#1991).
pub const ACTION_AUTONOMY_RECEIPT: &str = "security_disposition_autonomy";
pub const AUTONOMY_PROMOTED: &str = "promoted";
pub const AUTONOMY_REVIEW: &str = "review";

/// When an agent's dispositions in one class apply without review (#1991).
/// Package configuration: the same everywhere, read by
/// `sekaictl admin autonomy disposition-autonomy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AutonomyThresholds {
    /// Promoted at or above this precision, in basis points.
    pub min_precision_bps: u32,
    /// And at or below this overturn rate, in basis points.
    pub max_overturn_bps: u32,
    #[serde(skip)]
    pub window: PrecisionWindow,
    /// The minimum resolved count; below it a group stays under review.
    pub min_resolved: u32,
}

impl AutonomyThresholds {
    /// 95% precision and at most 5% overturned, over the production window.
    pub const fn production() -> Self {
        let window = PrecisionWindow::production();
        Self {
            min_precision_bps: 9_500,
            max_overturn_bps: 500,
            window,
            min_resolved: window.min_resolved,
        }
    }

    /// Whether `row` earns unreviewed dispositions. An `incomplete` group
    /// never does.
    pub fn promotes(&self, row: &DispositionPrecision) -> bool {
        row.status == STATUS_MEASURED
            && row
                .precision_bps
                .is_some_and(|bps| bps >= self.min_precision_bps)
            && row
                .overturn_bps
                .is_some_and(|bps| bps <= self.max_overturn_bps)
    }
}

/// One group's precision and whether it applies dispositions unreviewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispositionAutonomy {
    #[serde(flatten)]
    pub precision: DispositionPrecision,
    pub promoted: bool,
}

/// Every agent group's precision against `thresholds`, as of `now_ms`.
/// Read-only: crossings are recorded when the agent next submits.
pub fn disposition_autonomy(
    db: &RuntimeDb,
    namespace: &str,
    thresholds: AutonomyThresholds,
    now_ms: i64,
) -> Result<Vec<DispositionAutonomy>, String> {
    Ok(
        disposition_precision(db, namespace, thresholds.window, now_ms)?
            .into_iter()
            .map(|precision| DispositionAutonomy {
                promoted: thresholds.promotes(&precision),
                precision,
            })
            .collect(),
    )
}

/// Whether `principal`'s `type_id` submission with `parameters_json` applies
/// without review: a disposition record or supersede by an agent whose
/// group (recorder, revision, finding class) meets the production
/// thresholds now. Admission calls this for agents only.
pub fn promotes_disposition(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    type_id: &str,
    parameters_json: &str,
    now_ms: i64,
) -> Result<bool, String> {
    promotes_disposition_with(
        db,
        namespace,
        principal,
        type_id,
        parameters_json,
        AutonomyThresholds::production(),
        now_ms,
    )
}

/// [`promotes_disposition`] against `thresholds`. When the group's standing
/// differs from its last receipt, records the crossing first, and promotes
/// only once that receipt is durable: an unrecorded promotion parks. Each
/// crossing's receipt id derives from the group and its position in the
/// group's history, read before the evidence, so instances racing on one
/// position record one receipt and a stale one cannot follow a newer one.
pub fn promotes_disposition_with(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    type_id: &str,
    parameters_json: &str,
    thresholds: AutonomyThresholds,
    now_ms: i64,
) -> Result<bool, String> {
    use crate::sekai::security_package::{ACTION_DISPOSITION_RECORD, ACTION_DISPOSITION_SUPERSEDE};
    if type_id != ACTION_DISPOSITION_RECORD && type_id != ACTION_DISPOSITION_SUPERSEDE {
        return Ok(false);
    }
    let Some(exposure_id) = serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()
        .and_then(|parameters| parameters.get("exposure_id")?.as_str().map(str::to_owned))
        .filter(|id| !id.trim().is_empty())
    else {
        return Ok(false);
    };
    let revision =
        crate::sekai::site_agent_instance::definition_revision_for(db, namespace, principal)?
            .unwrap_or_default();
    let class = finding_class(db, &exposure_id)?;
    // The history is read before the evidence: the receipt is written at
    // this position, so a worker whose evidence is older than a receipt
    // another worker wrote meanwhile collides on its id and parks, instead
    // of appending a stale standing after it.
    let target = format!("security-autonomy:{namespace}:{principal}:{revision}:{class}");
    let history = db.list_decisions(&crate::sekai::audit::DecisionFilter {
        action: Some(ACTION_AUTONOMY_RECEIPT.into()),
        target_id: Some(target.clone()),
        ..Default::default()
    })?;
    let row = disposition_precision(db, namespace, thresholds.window, now_ms)?
        .into_iter()
        .find(|row| {
            row.recorded_by == principal
                && row.recorder_revision == revision
                && row.finding_class == class
        })
        .unwrap_or_else(|| DispositionPrecision {
            recorded_by: principal.into(),
            recorder_revision: revision.clone(),
            finding_class: class.clone(),
            confirmed: 0,
            overturned: 0,
            pending: 0,
            status: STATUS_INCOMPLETE,
            precision_bps: None,
            overturn_bps: None,
        });
    let standing = |history: &[crate::sekai::audit::Decision]| {
        history
            .iter()
            .max_by_key(|receipt| sequence(receipt))
            .is_some_and(|latest| latest.outcome == AUTONOMY_PROMOTED)
    };
    let promoted = thresholds.promotes(&row);
    if promoted == standing(&history) {
        return Ok(promoted);
    }
    // After the highest surviving receipt: retention may purge older ones.
    let position = history
        .iter()
        .map(sequence)
        .max()
        .map_or(0, |last| last + 1);
    let outcome = if promoted {
        AUTONOMY_PROMOTED
    } else {
        AUTONOMY_REVIEW
    };
    let receipt = crate::sekai::audit::Decision {
        id: format!(
            "security-autonomy:{:x}",
            sha2::Sha256::digest(format!("{target}\n{position}").as_bytes())
        ),
        timestamp: now_ms,
        actor: "security-autonomy".into(),
        action: ACTION_AUTONOMY_RECEIPT.into(),
        reason: format!(
            "{} crossed the disposition autonomy threshold for {class}",
            if promoted {
                "promoted:"
            } else {
                "returned to review:"
            }
        ),
        evidence: HashMap::from([
            ("namespace".into(), namespace.into()),
            ("recorded_by".into(), principal.into()),
            ("recorder_revision".into(), revision),
            ("finding_class".into(), class),
            ("sequence".into(), position.to_string()),
            ("status".into(), row.status.into()),
            ("confirmed".into(), row.confirmed.to_string()),
            ("overturned".into(), row.overturned.to_string()),
            (
                "precision_bps".into(),
                row.precision_bps
                    .map(|bps| bps.to_string())
                    .unwrap_or_default(),
            ),
            (
                "overturn_bps".into(),
                row.overturn_bps
                    .map(|bps| bps.to_string())
                    .unwrap_or_default(),
            ),
            (
                "min_precision_bps".into(),
                thresholds.min_precision_bps.to_string(),
            ),
            (
                "max_overturn_bps".into(),
                thresholds.max_overturn_bps.to_string(),
            ),
            ("min_resolved".into(), thresholds.min_resolved.to_string()),
        ]),
        target_id: target.clone(),
        outcome: outcome.into(),
    };
    if db
        .record_decisions_idempotently(std::slice::from_ref(&receipt))
        .is_ok()
    {
        return Ok(promoted);
    }
    // Another instance recorded this crossing first: its receipt stands.
    let history = db.list_decisions(&crate::sekai::audit::DecisionFilter {
        action: Some(ACTION_AUTONOMY_RECEIPT.into()),
        target_id: Some(target),
        ..Default::default()
    })?;
    Ok(promoted && standing(&history))
}

fn sequence(receipt: &crate::sekai::audit::Decision) -> u64 {
    receipt
        .evidence
        .get("sequence")
        .and_then(|position| position.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionRequest, ActionInstanceDecisionRequest,
    };
    use crate::sekai::object_security::PrincipalPolicyContext;
    use crate::sekai::security_package::{
        ACTION_DISPOSITION_RECORD, ACTION_DISPOSITION_SUPERSEDE, ACTION_EXPOSURE,
        ACTION_EXPOSURE_BASIS, ACTION_FINDING, PACKAGE_VERSION, VERDICT_UNKNOWN, install,
        reopen_changed_basis, reopen_expired,
    };
    use crate::sekai::service_principal::ServicePrincipalRegistration;
    use serde_json::{Value, json};

    const NAMESPACE: &str = "ops";
    const HUMAN: &str = "reviewer";
    const AGENT: &str = "svc-triage";
    const DAY: i64 = DAY_MS;
    /// Every disposition here is recorded on day 100.
    const RECORDED: i64 = 100 * DAY;

    fn window(min_resolved: u32) -> PrecisionWindow {
        PrecisionWindow {
            window_ms: 30 * DAY,
            settle_ms: 7 * DAY,
            min_resolved,
        }
    }

    fn request(type_id: &str, parameters: &Value) -> ActionInstanceAdmissionRequest {
        ActionInstanceAdmissionRequest {
            agent_turn: None,
            namespace: NAMESPACE.into(),
            type_id: type_id.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters.to_string(),
            idempotency_key: format!("{type_id}:{}", parameters["object_id"]),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: format!("sha256:{}", "a".repeat(64)),
            autonomous_envelope_id: String::new(),
            policy_context: PrincipalPolicyContext::default(),
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: String::new(),
            offline: None,
        }
    }

    /// A namespace admin grants a parked instance as reviewed.
    fn grant(db: &RuntimeDb, instance_id: &str, now_ms: i64) {
        ActionInstanceAdmission::new(db, None)
            .decide(
                ActionInstanceDecisionRequest {
                    instance_id: instance_id.into(),
                    decision: "grant".into(),
                    reason: "reviewed".into(),
                    decider_principals: vec![HUMAN.into()],
                    decider_is_namespace_admin: true,
                    delegating_actor: None,
                    execution_claim: None,
                },
                HUMAN,
                now_ms,
            )
            .unwrap();
    }

    /// Admits as `principal`; an agent's Action parks and is granted.
    fn admit_as(db: &RuntimeDb, principal: &str, type_id: &str, parameters: Value, now_ms: i64) {
        let outcome = ActionInstanceAdmission::new(db, None)
            .admit(request(type_id, &parameters), principal, now_ms)
            .unwrap();
        if outcome.instance.status == "parked" {
            grant(db, &outcome.instance.instance_id, now_ms);
        }
        let id = parameters["object_id"].as_str().unwrap();
        assert!(
            db.get_object(id).unwrap().is_some(),
            "{type_id} as {principal}: {} {}",
            outcome.instance.status,
            outcome.instance.deny_reason
        );
    }

    /// The package, an agent principal, and `exposures` exposures of one
    /// finding in `class`.
    fn plane(class: &str, exposures: usize) -> RuntimeDb {
        let db = RuntimeDb::memory();
        install(&db, NAMESPACE, HUMAN, 1_000).unwrap();
        db.put_service_principal(&ServicePrincipalRegistration {
            principal: AGENT.into(),
            tenant_id: String::new(),
            namespaces: vec![NAMESPACE.into()],
            action_types: vec![
                ACTION_DISPOSITION_RECORD.into(),
                ACTION_DISPOSITION_SUPERSEDE.into(),
            ],
            registered_by: HUMAN.into(),
            created_at_ms: 1,
            updated_at_ms: 1,
        })
        .unwrap();
        let mut finding = json!({
            "object_id": "f-1",
            "source": "scanner",
            "component": "openssl",
            "version_range": "<3.0.8",
            "problem_signature": "sig-1",
            "reported_severity": "high",
        });
        if !class.is_empty() {
            finding["finding_class"] = class.into();
        }
        admit_as(&db, HUMAN, ACTION_FINDING, finding, 2_000);
        for index in 1..=exposures {
            admit_as(
                &db,
                HUMAN,
                ACTION_EXPOSURE,
                json!({
                    "object_id": format!("e-{index}"),
                    "finding_id": "f-1",
                    "release": format!("api@1.{index}.0"),
                    "environment": "prod",
                    "verdict": VERDICT_UNKNOWN,
                }),
                2_000,
            );
        }
        db
    }

    fn disposition(id: &str, exposure: &str, decision: &str, supersedes: Option<&str>) -> Value {
        let mut parameters = json!({
            "object_id": id,
            "exposure_id": exposure,
            "disposition": decision,
            "dependency_closure_digest": "sha256:closure",
            "release_digest": "sha256:release",
            "configuration_digest": "sha256:config",
            "advisory_revision": "GHSA-1:3",
            "expires_at_ms": RECORDED + 60 * DAY,
        });
        if let Some(previous) = supersedes {
            parameters["supersedes"] = previous.into();
        }
        parameters
    }

    fn record(db: &RuntimeDb, principal: &str, id: &str, exposure: &str, decision: &str) {
        admit_as(
            db,
            principal,
            ACTION_DISPOSITION_RECORD,
            disposition(id, exposure, decision, None),
            RECORDED,
        );
    }

    fn supersede(db: &RuntimeDb, principal: &str, id: &str, previous: &str, decision: &str) {
        let exposure = db.get_object(previous).unwrap().unwrap().properties["exposure_id"].clone();
        admit_as(
            db,
            principal,
            ACTION_DISPOSITION_SUPERSEDE,
            disposition(id, &exposure, decision, Some(previous)),
            RECORDED + DAY,
        );
    }

    fn only(rows: Vec<DispositionPrecision>) -> DispositionPrecision {
        assert_eq!(rows.len(), 1, "{rows:?}");
        rows.into_iter().next().unwrap()
    }

    #[test]
    fn the_recorder_is_stamped_from_the_submitter() {
        let db = plane("", 1);
        record(&db, AGENT, "d-1", "e-1", "false-positive");
        let stamped = db.get_object("d-1").unwrap().unwrap();
        assert_eq!(stamped.properties[PROPERTY_RECORDED_BY], AGENT);
        assert_eq!(stamped.properties[PROPERTY_RECORDER_KIND], RECORDER_AGENT);
        assert!(!stamped.properties.contains_key(PROPERTY_RECORDER_REVISION));
    }

    /// Three human overturns and one human confirmation in one class read a
    /// 0.25 precision for that class.
    #[test]
    fn human_supersedes_resolve_an_agents_dispositions() {
        let db = plane("injection", 4);
        for index in 1..=4 {
            record(
                &db,
                AGENT,
                &format!("d-{index}"),
                &format!("e-{index}"),
                "false-positive",
            );
        }
        for index in 1..=3 {
            supersede(
                &db,
                HUMAN,
                &format!("h-{index}"),
                &format!("d-{index}"),
                "fixed",
            );
        }
        supersede(&db, HUMAN, "h-4", "d-4", "false-positive");

        let row =
            only(disposition_precision(&db, NAMESPACE, window(4), RECORDED + 2 * DAY).unwrap());
        assert_eq!(
            (row.recorded_by.as_str(), row.finding_class.as_str()),
            (AGENT, "injection")
        );
        assert_eq!((row.confirmed, row.overturned, row.pending), (1, 3, 0));
        assert_eq!(row.status, STATUS_MEASURED);
        assert_eq!(row.precision_bps, Some(2_500));
        assert_eq!(row.overturn_bps, Some(7_500));
    }

    #[test]
    fn below_the_minimum_resolved_count_reads_incomplete() {
        let db = plane("", 2);
        record(&db, AGENT, "d-1", "e-1", "false-positive");
        record(&db, AGENT, "d-2", "e-2", "false-positive");
        supersede(&db, HUMAN, "h-1", "d-1", "false-positive");

        let row =
            only(disposition_precision(&db, NAMESPACE, window(2), RECORDED + 2 * DAY).unwrap());
        assert_eq!(row.finding_class, UNCLASSIFIED);
        assert_eq!((row.confirmed, row.overturned, row.pending), (1, 0, 1));
        assert_eq!(row.status, STATUS_INCOMPLETE);
        assert_eq!((row.precision_bps, row.overturn_bps), (None, None));
    }

    /// Unchallenged past the settle period confirms; another agent's
    /// supersede is no human judgement; a human's own dispositions and
    /// anything outside the window are not counted.
    #[test]
    fn settling_agent_successors_humans_and_the_window() {
        let db = plane("", 3);
        record(&db, AGENT, "d-1", "e-1", "false-positive");
        record(&db, AGENT, "d-2", "e-2", "false-positive");
        supersede(&db, AGENT, "d-3", "d-2", "mitigated");
        record(&db, HUMAN, "h-1", "e-3", "fixed");

        let early =
            only(disposition_precision(&db, NAMESPACE, window(1), RECORDED + 2 * DAY).unwrap());
        assert_eq!(
            (early.confirmed, early.overturned, early.pending),
            (0, 0, 3)
        );
        let settled =
            only(disposition_precision(&db, NAMESPACE, window(1), RECORDED + 8 * DAY).unwrap());
        // d-1 and d-3 settle; d-2 stays pending under its agent successor.
        assert_eq!(
            (settled.confirmed, settled.overturned, settled.pending),
            (2, 0, 1)
        );
        assert!(
            disposition_precision(&db, NAMESPACE, window(1), RECORDED + 31 * DAY)
                .unwrap()
                .is_empty()
        );
    }

    /// A reopen for a changed basis fact overturns; one for the
    /// disposition's own expiry confirms.
    #[test]
    fn a_basis_reopen_overturns_and_an_expiry_reopen_confirms() {
        let db = plane("", 2);
        record(&db, AGENT, "d-1", "e-1", "false-positive");
        admit_as(
            &db,
            HUMAN,
            ACTION_EXPOSURE_BASIS,
            json!({"object_id": "e-1", "dependency_closure_digest": "sha256:other"}),
            RECORDED + DAY,
        );
        assert_eq!(
            reopen_changed_basis(&db, NAMESPACE, HUMAN, 0, RECORDED + DAY)
                .unwrap()
                .reopened
                .len(),
            1
        );
        let mut expiring = disposition("d-2", "e-2", "false-positive", None);
        expiring["expires_at_ms"] = (RECORDED + DAY).into();
        admit_as(&db, AGENT, ACTION_DISPOSITION_RECORD, expiring, RECORDED);
        assert_eq!(
            reopen_expired(&db, NAMESPACE, HUMAN, RECORDED + 2 * DAY)
                .unwrap()
                .len(),
            1
        );

        let row =
            only(disposition_precision(&db, NAMESPACE, window(1), RECORDED + 3 * DAY).unwrap());
        assert_eq!((row.confirmed, row.overturned, row.pending), (1, 1, 0));
    }

    /// Retiring the agent's service principal later changes nothing it
    /// recorded, and a measurement as of a time before the human's overturn
    /// does not see it.
    #[test]
    fn history_is_as_recorded_and_as_of_the_measurement() {
        let db = plane("", 1);
        record(&db, AGENT, "d-1", "e-1", "false-positive");
        supersede(&db, HUMAN, "h-1", "d-1", "fixed");
        assert!(db.delete_service_principal(AGENT, "").unwrap());

        let later =
            only(disposition_precision(&db, NAMESPACE, window(1), RECORDED + 2 * DAY).unwrap());
        assert_eq!(
            (later.confirmed, later.overturned, later.pending),
            (0, 1, 0)
        );
        let before =
            only(disposition_precision(&db, NAMESPACE, window(1), RECORDED + DAY / 2).unwrap());
        assert_eq!(
            (before.confirmed, before.overturned, before.pending),
            (0, 0, 1)
        );
    }

    /// An agent deregistered while its disposition waits for review is
    /// still recorded as the agent it was when it submitted.
    #[test]
    fn a_parked_disposition_keeps_its_submission_classification() {
        let db = plane("", 1);
        let parked = ActionInstanceAdmission::new(&db, None)
            .admit(
                request(
                    ACTION_DISPOSITION_RECORD,
                    &disposition("d-1", "e-1", "false-positive", None),
                ),
                AGENT,
                RECORDED,
            )
            .unwrap();
        assert_eq!(parked.instance.status, "parked");
        assert!(db.delete_service_principal(AGENT, "").unwrap());
        grant(&db, &parked.instance.instance_id, RECORDED);
        let stamped = db.get_object("d-1").unwrap().unwrap();
        assert_eq!(stamped.properties[PROPERTY_RECORDER_KIND], RECORDER_AGENT);
    }

    fn lenient() -> AutonomyThresholds {
        AutonomyThresholds {
            min_precision_bps: 5_000,
            max_overturn_bps: 5_000,
            window: window(2),
            min_resolved: 2,
        }
    }

    /// Whether the agent's next disposition on `exposure` applies unreviewed.
    fn gate(db: &RuntimeDb, exposure: &str, thresholds: AutonomyThresholds, now_ms: i64) -> bool {
        promotes_disposition_with(
            db,
            NAMESPACE,
            AGENT,
            ACTION_DISPOSITION_RECORD,
            &json!({"exposure_id": exposure}).to_string(),
            thresholds,
            now_ms,
        )
        .unwrap()
    }

    fn receipts(db: &RuntimeDb) -> Vec<crate::sekai::audit::Decision> {
        let mut all = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some(ACTION_AUTONOMY_RECEIPT.into()),
                ..Default::default()
            })
            .unwrap();
        all.sort_by_key(sequence);
        all
    }

    /// Promoted on good evidence, returned to review once the overturn rate
    /// climbs, promoted again when it recovers; each crossing is one
    /// receipt naming the group, the metrics and the threshold (#1991). The
    /// agent records everything first; human judgements then arrive over
    /// days, and the gate is read as of each day.
    #[test]
    fn crossings_either_way_are_receipts() {
        let db = plane("injection", 8);
        for index in 1..=7 {
            record(
                &db,
                AGENT,
                &format!("d-{index}"),
                &format!("e-{index}"),
                "false-positive",
            );
        }
        let judge = |index: u32, decision: &str, day: i64| {
            let previous = format!("d-{index}");
            admit_as(
                &db,
                HUMAN,
                ACTION_DISPOSITION_SUPERSEDE,
                disposition(
                    &format!("h-{index}"),
                    &format!("e-{index}"),
                    decision,
                    Some(&previous),
                ),
                RECORDED + day * DAY,
            );
        };
        judge(1, "false-positive", 1);
        judge(2, "false-positive", 1);
        for index in 3..=5 {
            judge(index, "fixed", 3);
        }
        judge(6, "false-positive", 5);
        judge(7, "false-positive", 5);

        let at = |day: i64| gate(&db, "e-8", lenient(), RECORDED + day * DAY);
        assert!(at(2));
        assert!(at(2), "a standing promotion records nothing");
        assert!(!at(4));
        assert!(at(6));

        let history = receipts(&db);
        let outcomes: Vec<_> = history
            .iter()
            .map(|receipt| receipt.outcome.as_str())
            .collect();
        assert_eq!(
            outcomes,
            [AUTONOMY_PROMOTED, AUTONOMY_REVIEW, AUTONOMY_PROMOTED]
        );
        let demoted = &history[1].evidence;
        assert_eq!(demoted["recorded_by"], AGENT);
        assert_eq!(demoted["finding_class"], "injection");
        assert_eq!(demoted["precision_bps"], "4000");
        assert_eq!(demoted["overturn_bps"], "6000");
        assert_eq!(demoted["min_precision_bps"], "5000");
    }

    /// Too little evidence never promotes, however good it is.
    #[test]
    fn an_incomplete_agent_is_never_promoted() {
        let db = plane("", 2);
        record(&db, AGENT, "d-1", "e-1", "false-positive");
        supersede(&db, HUMAN, "h-1", "d-1", "false-positive");
        assert!(!gate(&db, "e-2", lenient(), RECORDED + 2 * DAY));
        assert!(receipts(&db).is_empty());
        let rows = disposition_autonomy(&db, NAMESPACE, lenient(), RECORDED + 2 * DAY).unwrap();
        let [row] = rows.as_slice() else {
            panic!("{rows:?}")
        };
        assert_eq!(row.precision.status, STATUS_INCOMPLETE);
        assert!(!row.promoted);
    }

    /// Through admission at the production thresholds: an agent parks until
    /// twenty settled dispositions earn it, then records directly.
    #[test]
    fn a_promoted_agent_records_without_review() {
        let db = plane("", 21);
        for index in 1..=20 {
            record(
                &db,
                AGENT,
                &format!("d-{index}"),
                &format!("e-{index}"),
                "false-positive",
            );
        }
        let submit = |now_ms: i64, id: &str| {
            ActionInstanceAdmission::new(&db, None)
                .admit(
                    request(
                        ACTION_DISPOSITION_RECORD,
                        &disposition(id, "e-21", "false-positive", None),
                    ),
                    AGENT,
                    now_ms,
                )
                .unwrap()
                .instance
        };
        let early = submit(RECORDED + DAY, "d-21");
        assert_eq!(early.status, "parked");
        assert_eq!(
            early.review.queue_id,
            crate::sekai::security_package::DISPOSITION_REVIEW_QUEUE
        );
        assert!(receipts(&db).is_empty());

        let mut later = disposition("d-22", "e-21", "false-positive", None);
        later["object_id"] = "d-22".into();
        let settled = RECORDED + 15 * DAY;
        let admitted = ActionInstanceAdmission::new(&db, None)
            .admit(request(ACTION_DISPOSITION_RECORD, &later), AGENT, settled)
            .unwrap()
            .instance;
        assert_eq!(admitted.status, "admitted", "{}", admitted.deny_reason);
        assert!(db.get_object("d-22").unwrap().is_some());
        assert_eq!(receipts(&db).len(), 1);
    }

    /// Retention may purge the oldest receipts; the next crossing still
    /// follows the newest one.
    #[test]
    fn a_crossing_follows_the_newest_receipt_after_retention() {
        let db = plane("", 3);
        for index in 1..=2 {
            record(
                &db,
                AGENT,
                &format!("d-{index}"),
                &format!("e-{index}"),
                "false-positive",
            );
        }
        for index in 1..=2 {
            admit_as(
                &db,
                HUMAN,
                ACTION_DISPOSITION_SUPERSEDE,
                disposition(
                    &format!("h-{index}"),
                    &format!("e-{index}"),
                    if index == 1 {
                        "false-positive"
                    } else {
                        "fixed"
                    },
                    Some(&format!("d-{index}")),
                ),
                RECORDED + index as i64 * DAY,
            );
        }
        let strict = AutonomyThresholds {
            min_precision_bps: 10_000,
            max_overturn_bps: 0,
            window: window(1),
            min_resolved: 1,
        };
        assert!(gate(&db, "e-3", strict, RECORDED + DAY + DAY / 2));
        assert!(!gate(&db, "e-3", strict, RECORDED + 3 * DAY));
        // Purges the ledger prefix up to the second receipt, the first included.
        db.purge_old_records(RECORDED + 3 * DAY).unwrap();
        let surviving = receipts(&db);
        assert_eq!(surviving.iter().map(sequence).collect::<Vec<_>>(), [1]);
        // One confirmed and one overturned meets the lenient thresholds.
        assert!(gate(&db, "e-3", lenient(), RECORDED + 3 * DAY));
        let history = receipts(&db);
        assert_eq!(history.iter().map(sequence).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(history[1].outcome, AUTONOMY_PROMOTED);
    }
}
