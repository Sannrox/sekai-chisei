//! Remediation plans and mitigating-control Actions (#1669).
//!
//! A types-only extension of the security package (ADR 0135): a remediation
//! is a typed plan on an exposure; each catalogue control is a separate,
//! reversible Action applied only after that plan is decided. Freeze takes
//! effect at the next admission. Gateway tool-disable, outbound deny, and
//! marking raise are recorded as decided mitigations (`gateway_audit` or
//! `marking_audit` pending) until their plane applies them.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, Object};
use crate::sekai::action_instance::{PlanReference, STATUS_ADMITTED, STATUS_PARKED};
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use crate::sekai::security_package::{
    DISPOSITION_FIXED, KIND_DISPOSITION, KIND_EXPOSURE, NO_MARKINGS, PACKAGE_VERSION,
};
use crate::sekai::write_freeze::{MODE_BLOCK_WRITES, SCOPE_ACTION, WriteFreeze};

pub const KIND_REMEDIATION: &str = "security_remediation";
pub const KIND_MITIGATION: &str = "security_mitigation";

pub const ACTION_REMEDIATION_PROPOSE: &str = "security.remediation.propose";
pub const ACTION_MITIGATION_APPLY: &str = "security.mitigation.apply";
pub const ACTION_MITIGATION_PROPOSE_LIFT: &str = "security.mitigation.propose_lift";
pub const ACTION_MITIGATION_LIFT: &str = "security.mitigation.lift";

pub const REMEDIATION_REVIEW_QUEUE: &str = "security.remediations";

pub const CONTROL_FREEZE: &str = "freeze";
pub const CONTROL_MARKING_RAISE: &str = "marking_raise";
pub const CONTROL_GATEWAY_TOOL: &str = "gateway_tool_disable";
pub const CONTROL_OUTBOUND_DENY: &str = "outbound_deny";

pub const STATE_APPLIED: &str = "applied";
pub const STATE_LIFT_PROPOSED: &str = "lift_proposed";
pub const STATE_LIFTED: &str = "lifted";

pub const GATEWAY_AUDIT_PENDING: &str = "pending";
pub const MARKING_AUDIT_PENDING: &str = "pending";

const CATALOGUE: [&str; 4] = [
    CONTROL_FREEZE,
    CONTROL_MARKING_RAISE,
    CONTROL_GATEWAY_TOOL,
    CONTROL_OUTBOUND_DENY,
];

pub fn is_remediation_kind(kind: &str) -> bool {
    kind == KIND_REMEDIATION || kind == KIND_MITIGATION
}

pub fn is_remediation_action(type_id: &str) -> bool {
    [
        ACTION_REMEDIATION_PROPOSE,
        ACTION_MITIGATION_APPLY,
        ACTION_MITIGATION_PROPOSE_LIFT,
        ACTION_MITIGATION_LIFT,
    ]
    .contains(&type_id)
}

/// Park apply and lift, and park a proposal that is two-person, a production
/// change, high criticality, or that touches marked data. Low-tier proposals
/// auto-admit. Lift proposals from a fixed disposition auto-admit.
pub fn should_park(
    db: &RuntimeDb,
    namespace: &str,
    type_id: &str,
    parameters_json: &str,
) -> Result<bool, String> {
    match type_id {
        ACTION_MITIGATION_APPLY | ACTION_MITIGATION_LIFT => Ok(true),
        ACTION_MITIGATION_PROPOSE_LIFT => Ok(false),
        ACTION_REMEDIATION_PROPOSE => proposal_needs_human(db, namespace, parameters_json),
        _ => Ok(false),
    }
}

fn proposal_needs_human(
    db: &RuntimeDb,
    namespace: &str,
    parameters_json: &str,
) -> Result<bool, String> {
    let parameters: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|error| format!("remediation parameters: {error}"))?;
    if truthy(parameters.get("two_person")) {
        return Ok(true);
    }
    if string_param(&parameters, "rollout_ref").is_some() {
        return Ok(true);
    }
    match string_param(&parameters, "asset_criticality") {
        Some("high" | "critical") => return Ok(true),
        Some("low" | "medium") | None => {}
        Some(other) => {
            return Err(format!(
                "asset_criticality must be low, medium, high or critical, not {other}"
            ));
        }
    }
    let exposure_id = string_param(&parameters, "exposure_id")
        .ok_or_else(|| "exposure_id is required".to_string())?;
    let Some(exposure) = db
        .get_object(exposure_id)?
        .filter(|exposure| exposure.namespace == namespace && exposure.kind == KIND_EXPOSURE)
    else {
        return Ok(true);
    };
    Ok(exposure_is_marked(&exposure))
}

/// Receipt attributes that link finding, exposure, decision and gateway audit.
pub fn receipt_chain(object: &Object, operation_id: &str) -> BTreeMap<String, String> {
    if object.kind != KIND_MITIGATION {
        return BTreeMap::new();
    }
    let mut attributes = BTreeMap::new();
    for key in [
        "finding_id",
        "exposure_id",
        "gateway_audit",
        "marking_audit",
    ] {
        if let Some(value) = object.properties.get(key).filter(|value| !value.is_empty()) {
            attributes.insert(key.into(), value.clone());
        }
    }
    if !operation_id.is_empty() {
        attributes.insert("decision".into(), operation_id.into());
    }
    attributes
}

pub fn validate_object_write(db: &RuntimeDb, object: &mut Object) -> Result<String, String> {
    match object.kind.as_str() {
        KIND_REMEDIATION => validate_remediation(db, object),
        KIND_MITIGATION => validate_mitigation(db, object),
        other => Err(format!("{other} is not a remediation package kind")),
    }
}

pub fn references(db: &RuntimeDb, object: &Object) -> Result<Vec<PlanReference>, String> {
    let mut references = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for id in fenced_ids(db, object)? {
        if !seen.insert(id.clone()) {
            continue;
        }
        references.push(match db.get_object(&id)? {
            Some(found) => PlanReference::Present(found),
            None => PlanReference::Absent(id),
        });
    }
    Ok(references)
}

pub fn reference_ids(object: &Object) -> Vec<String> {
    let property = |name: &str| {
        object
            .properties
            .get(name)
            .filter(|id| !id.trim().is_empty())
            .cloned()
    };
    match object.kind.as_str() {
        KIND_REMEDIATION => property("exposure_id").into_iter().collect(),
        KIND_MITIGATION => property("remediation_id")
            .into_iter()
            .chain(property("exposure_id"))
            .collect(),
        _ => Vec::new(),
    }
}

/// Apply stamps `exposure_id` after references are snapshotted. Fence the
/// exposure through the remediation so a concurrent marking raise refuses.
fn fenced_ids(db: &RuntimeDb, object: &Object) -> Result<Vec<String>, String> {
    let mut ids = reference_ids(object);
    if object.kind != KIND_MITIGATION
        || object
            .properties
            .get("exposure_id")
            .is_some_and(|id| !id.trim().is_empty())
    {
        return Ok(ids);
    }
    let Some(remediation_id) = object
        .properties
        .get("remediation_id")
        .filter(|id| !id.trim().is_empty())
    else {
        return Ok(ids);
    };
    if let Some(exposure_id) = db
        .get_object(remediation_id)?
        .and_then(|remediation| remediation.properties.get("exposure_id").cloned())
        .filter(|id| !id.trim().is_empty())
        && !ids.contains(&exposure_id)
    {
        ids.push(exposure_id);
    }
    Ok(ids)
}

/// Enable a freeze before the mitigation object is durable so a freeze-row
/// failure cannot leave `state=applied` while the target type still admits.
pub(crate) fn enable_applied_freeze(
    db: &RuntimeDb,
    object: &Object,
    now_ms: i64,
) -> Result<(), String> {
    if object.kind != KIND_MITIGATION {
        return Ok(());
    }
    if object.properties.get("state").map(String::as_str) != Some(STATE_APPLIED) {
        return Ok(());
    }
    apply_freeze(db, object, now_ms)
}

/// Drop a freeze enabled before persist when the mitigation did not land.
/// An object already in the store is a landing (including a concurrent grant
/// of the same apply), so keepers on that id stay. Other applied keepers on
/// the same Action type stay.
pub(crate) fn rollback_unapplied_freeze(
    db: &RuntimeDb,
    object: &Object,
    now_ms: i64,
) -> Result<(), String> {
    if object.kind != KIND_MITIGATION {
        return Ok(());
    }
    if object.properties.get("control").map(String::as_str) != Some(CONTROL_FREEZE) {
        return Ok(());
    }
    if object.properties.get("state").map(String::as_str) != Some(STATE_APPLIED) {
        return Ok(());
    }
    if db
        .get_object(&object.id)?
        .is_some_and(|landed| landed.kind == KIND_MITIGATION)
    {
        return Ok(());
    }
    let Some(target) = object
        .properties
        .get("target")
        .map(String::as_str)
        .filter(|target| !target.is_empty())
    else {
        return Ok(());
    };
    lift_security_freeze(db, object, target, now_ms)
}

/// After a mitigation write is durable, lift a freeze or catch up an enable
/// from a recovered admission (`apply` and `grant_parked` enable first).
/// After a `fixed` disposition, propose lifting every active mitigation.
pub fn complete_object_write(db: &RuntimeDb, object: &Object, actor: &str, now_ms: i64) {
    match object.kind.as_str() {
        KIND_MITIGATION => {
            let _ = apply_freeze(db, object, now_ms);
        }
        KIND_DISPOSITION
            if object.properties.get("disposition").map(String::as_str)
                == Some(DISPOSITION_FIXED) =>
        {
            let _ = propose_lifts_for_fixed(db, object, actor, now_ms);
        }
        _ => {}
    }
}

fn validate_remediation(db: &RuntimeDb, object: &mut Object) -> Result<String, String> {
    if db.get_object(&object.id)?.is_some() {
        return Err("a remediation cannot be changed; propose a new plan".into());
    }
    let controls = parse_controls(required(object, "controls")?)?;
    if controls.is_empty() {
        return Err("controls must name at least one catalogue entry".into());
    }
    let exposure = require_exposure(db, object)?;
    if let Some(criticality) = object.properties.get("asset_criticality") {
        match criticality.as_str() {
            "low" | "medium" | "high" | "critical" => {}
            other => {
                return Err(format!(
                    "asset_criticality must be low, medium, high or critical, not {other}"
                ));
            }
        }
    }
    require_marking_for_exposure(db, object, &exposure)?;
    object.properties.insert(
        "finding_id".into(),
        required(&exposure, "finding_id")?.to_string(),
    );
    let identity = remediation_identity(object, &controls);
    Ok(identity)
}

fn validate_mitigation(db: &RuntimeDb, object: &mut Object) -> Result<String, String> {
    let existing = db.get_object(&object.id)?;
    let state = required(object, "state")?;
    match (existing.as_ref(), state) {
        (None, STATE_APPLIED) => validate_apply(db, object),
        (Some(previous), STATE_LIFT_PROPOSED) => {
            validate_state_change(previous, STATE_APPLIED, STATE_LIFT_PROPOSED)?;
            Ok(previous.external_id.clone())
        }
        (Some(previous), STATE_LIFTED) => {
            if previous.properties.get("state").map(String::as_str) != Some(STATE_APPLIED)
                && previous.properties.get("state").map(String::as_str) != Some(STATE_LIFT_PROPOSED)
            {
                return Err(format!(
                    "mitigation {} is not applied; lift an applied control",
                    previous.id
                ));
            }
            Ok(previous.external_id.clone())
        }
        (Some(_), STATE_APPLIED) => Err("a mitigation cannot be applied twice".into()),
        (None, other) => Err(format!("a new mitigation must be applied, not {other}")),
        (Some(previous), other) => {
            Err(format!("mitigation {} cannot move to {other}", previous.id))
        }
    }
}

fn validate_apply(db: &RuntimeDb, object: &mut Object) -> Result<String, String> {
    let remediation = require_remediation(db, object)?;
    let control = required(object, "control")?.to_string();
    let target = required(object, "target")?.to_string();
    if !CATALOGUE.contains(&control.as_str()) {
        return Err(format!(
            "control must be {}, not {control}",
            CATALOGUE.join(", ")
        ));
    }
    if control == CONTROL_FREEZE && target.starts_with("security.mitigation.") {
        return Err("a freeze cannot target a mitigation Action".into());
    }
    let controls = parse_controls(required(&remediation, "controls")?)?;
    if !controls
        .iter()
        .any(|(kind, item)| kind == &control && item == &target)
    {
        return Err(format!(
            "remediation {} has no {control}:{target} control",
            remediation.id
        ));
    }
    require_marking_for_exposure(db, object, &require_exposure(db, &remediation)?)?;
    object.properties.insert(
        "exposure_id".into(),
        required(&remediation, "exposure_id")?.to_string(),
    );
    object.properties.insert(
        "finding_id".into(),
        required(&remediation, "finding_id")?.to_string(),
    );
    if control == CONTROL_GATEWAY_TOOL || control == CONTROL_OUTBOUND_DENY {
        object
            .properties
            .insert("gateway_audit".into(), GATEWAY_AUDIT_PENDING.into());
    }
    if control == CONTROL_MARKING_RAISE {
        object
            .properties
            .insert("marking_audit".into(), MARKING_AUDIT_PENDING.into());
    }
    Ok(mitigation_identity(&remediation.id, &control, &target))
}

fn validate_state_change(previous: &Object, from: &str, to: &str) -> Result<(), String> {
    if previous.properties.get("state").map(String::as_str) != Some(from) {
        return Err(format!(
            "mitigation {} is not {from}; cannot move to {to}",
            previous.id
        ));
    }
    Ok(())
}

fn freeze_reason_for(mitigation_id: &str) -> String {
    format!("security mitigation {mitigation_id}")
}

fn is_security_mitigation_freeze(reason: &str) -> bool {
    reason.starts_with("security mitigation ")
}

fn action_freeze(db: &RuntimeDb, target: &str) -> Result<Option<WriteFreeze>, String> {
    Ok(db
        .list_write_freezes()?
        .into_iter()
        .find(|freeze| freeze.scope_kind == SCOPE_ACTION && freeze.scope_value == target))
}

fn apply_freeze(db: &RuntimeDb, object: &Object, now_ms: i64) -> Result<(), String> {
    if object.properties.get("control").map(String::as_str) != Some(CONTROL_FREEZE) {
        return Ok(());
    }
    let target = required(object, "target")?;
    match object.properties.get("state").map(String::as_str) {
        Some(STATE_APPLIED) => enable_security_freeze(db, object, target, now_ms),
        Some(STATE_LIFTED) => lift_security_freeze(db, object, target, now_ms),
        _ => Ok(()),
    }
}

fn enable_security_freeze(
    db: &RuntimeDb,
    object: &Object,
    target: &str,
    now_ms: i64,
) -> Result<(), String> {
    let reason = freeze_reason_for(&object.id);
    match action_freeze(db, target)? {
        Some(freeze)
            if freeze.enabled
                && freeze.mode == MODE_BLOCK_WRITES
                && (freeze.reason == reason || !is_security_mitigation_freeze(&freeze.reason)) =>
        {
            Ok(())
        }
        Some(freeze)
            if freeze.enabled
                && freeze.mode == MODE_BLOCK_WRITES
                && is_security_mitigation_freeze(&freeze.reason)
                && db
                    .get_object(&object.id)?
                    .is_some_and(|landed| landed.kind == KIND_MITIGATION) =>
        {
            Ok(())
        }
        _ => db.set_write_freeze(&WriteFreeze {
            scope_kind: SCOPE_ACTION.into(),
            scope_value: target.into(),
            mode: MODE_BLOCK_WRITES.into(),
            reason,
            enabled: true,
            updated_ms: now_ms,
        }),
    }
}

fn lift_security_freeze(
    db: &RuntimeDb,
    object: &Object,
    target: &str,
    now_ms: i64,
) -> Result<(), String> {
    let reason = freeze_reason_for(&object.id);
    let keeper = applied_freeze_mitigations(db, target)?
        .into_iter()
        .find(|mitigation| mitigation.id != object.id);
    match action_freeze(db, target)? {
        Some(freeze) if freeze.enabled && freeze.reason == reason => {
            db.set_write_freeze(&WriteFreeze {
                scope_kind: SCOPE_ACTION.into(),
                scope_value: target.into(),
                mode: MODE_BLOCK_WRITES.into(),
                reason: keeper
                    .as_ref()
                    .map(|keeper| freeze_reason_for(&keeper.id))
                    .unwrap_or_else(|| freeze.reason.clone()),
                enabled: keeper.is_some(),
                updated_ms: now_ms,
            })
        }
        _ => Ok(()),
    }
}

/// Operator unfreeze is the same row as a security freeze. Refuse any write
/// that would stop blocking writes while a freeze mitigation is still applied.
pub(crate) fn refuse_unfreeze_while_applied(
    db: &RuntimeDb,
    freeze: &WriteFreeze,
) -> Result<(), String> {
    if freeze.scope_kind != SCOPE_ACTION {
        return Ok(());
    }
    if freeze.enabled && freeze.mode == MODE_BLOCK_WRITES {
        return Ok(());
    }
    let Some(keeper) = applied_freeze_mitigations(db, &freeze.scope_value)?
        .into_iter()
        .next()
    else {
        return Ok(());
    };
    Err(format!(
        "write freeze ({}/{}/{}) is held by security mitigation {}",
        freeze.scope_kind, freeze.scope_value, freeze.mode, keeper.id
    ))
}

fn propose_lifts_for_fixed(
    db: &RuntimeDb,
    disposition: &Object,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    let exposure_id = required(disposition, "exposure_id")?;
    let Some(head) = crate::sekai::security_package::disposition_chain_head(
        db,
        &disposition.namespace,
        exposure_id,
    )?
    else {
        return Ok(());
    };
    if head.id != disposition.id {
        return Ok(());
    }
    for mitigation in active_mitigations(db, &disposition.namespace, exposure_id)? {
        if !disposition_covers_mitigation(db, disposition, &mitigation)? {
            continue;
        }
        let parameters = serde_json::json!({
            "object_id": mitigation.id,
            "state": STATE_LIFT_PROPOSED,
        });
        let request = ActionInstanceAdmissionRequest {
            agent_turn: None,
            namespace: disposition.namespace.clone(),
            type_id: ACTION_MITIGATION_PROPOSE_LIFT.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters.to_string(),
            idempotency_key: format!("security.lift-proposal:{}", mitigation.id),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: String::new(),
            autonomous_envelope_id: String::new(),
            policy_context: Default::default(),
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: String::new(),
            offline: None,
        };
        let outcome = ActionInstanceAdmission::new(db, None).admit(request, actor, now_ms);
        match outcome {
            Ok(admitted)
                if admitted.instance.status == STATUS_ADMITTED
                    || admitted.instance.status == STATUS_PARKED => {}
            Ok(denied) => {
                return Err(format!(
                    "lift proposal for {} was {}: {}",
                    mitigation.id, denied.instance.status, denied.instance.deny_reason
                ));
            }
            Err(error) => {
                return Err(format!("lift proposal for {}: {error:?}", mitigation.id));
            }
        }
    }
    Ok(())
}

fn active_mitigations(
    db: &RuntimeDb,
    namespace: &str,
    exposure_id: &str,
) -> Result<Vec<Object>, String> {
    list_mitigations(db, Some(namespace), |object| {
        object.properties.get("exposure_id").map(String::as_str) == Some(exposure_id)
            && object.properties.get("state").map(String::as_str) == Some(STATE_APPLIED)
    })
}

/// SCOPE_ACTION freeze rows are cluster-global, so keepers are every freeze
/// still in force on that type (applied or lift-proposed), not only the
/// lifting object's namespace. Lift-proposed still holds until lift is granted.
fn applied_freeze_mitigations(db: &RuntimeDb, target: &str) -> Result<Vec<Object>, String> {
    list_mitigations(db, None, |object| {
        object.properties.get("control").map(String::as_str) == Some(CONTROL_FREEZE)
            && object.properties.get("target").map(String::as_str) == Some(target)
            && matches!(
                object.properties.get("state").map(String::as_str),
                Some(STATE_APPLIED | STATE_LIFT_PROPOSED)
            )
    })
}

fn list_mitigations(
    db: &RuntimeDb,
    namespace: Option<&str>,
    keep: impl Fn(&Object) -> bool,
) -> Result<Vec<Object>, String> {
    let mut found = Vec::new();
    let mut offset = 0i32;
    loop {
        let page = db.list_objects(&ListFilter {
            kind: Some(KIND_MITIGATION.into()),
            namespace: namespace.map(str::to_string),
            limit: 100,
            offset,
            ..Default::default()
        })?;
        let done = page.len() < 100;
        offset += i32::try_from(page.len()).map_err(|error| error.to_string())?;
        found.extend(page.into_iter().filter(&keep));
        if done {
            return Ok(found);
        }
    }
}

fn parse_controls(value: &str) -> Result<Vec<(String, String)>, String> {
    let mut controls = Vec::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (kind, target) = entry.split_once(':').ok_or_else(|| {
            format!("control {entry:?} must be kind:target from the mitigation catalogue")
        })?;
        if !CATALOGUE.contains(&kind) {
            return Err(format!(
                "control {kind} is not in the catalogue ({})",
                CATALOGUE.join(", ")
            ));
        }
        if target.trim().is_empty() || target.trim() != target || target.contains(',') {
            return Err(format!("control {kind} needs a canonical non-empty target"));
        }
        controls.push((kind.to_string(), target.to_string()));
    }
    Ok(controls)
}

fn require_exposure(db: &RuntimeDb, object: &Object) -> Result<Object, String> {
    let exposure_id = required(object, "exposure_id")?;
    db.get_object(exposure_id)?
        .filter(|exposure| exposure.namespace == object.namespace && exposure.kind == KIND_EXPOSURE)
        .ok_or_else(|| format!("exposure {exposure_id} not found in this namespace"))
}

fn require_remediation(db: &RuntimeDb, object: &Object) -> Result<Object, String> {
    let remediation_id = required(object, "remediation_id")?;
    db.get_object(remediation_id)?
        .filter(|remediation| {
            remediation.namespace == object.namespace && remediation.kind == KIND_REMEDIATION
        })
        .ok_or_else(|| {
            format!("remediation {remediation_id} not found; apply only after the plan is decided")
        })
}

fn disposition_covers_mitigation(
    db: &RuntimeDb,
    disposition: &Object,
    mitigation: &Object,
) -> Result<bool, String> {
    let Some(needed) = crate::sekai::markings::object_marking_token(mitigation) else {
        return Ok(true);
    };
    let held = crate::sekai::markings::object_marking_token(disposition).unwrap_or_default();
    if held.is_empty() {
        return Ok(false);
    }
    let lattice = db
        .get_classification_lattice(&disposition.namespace)?
        .unwrap_or_else(|| {
            crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                &disposition.namespace,
            )
        });
    lattice.dominates(held, needed)
}

fn require_marking_for_exposure(
    db: &RuntimeDb,
    object: &Object,
    exposure: &Object,
) -> Result<(), String> {
    let mut needed = Vec::new();
    if let Some(marking) = crate::sekai::markings::object_marking_token(exposure) {
        needed.push(marking.to_string());
    }
    if let Some(markings) = exposure.properties.get("reachable_markings") {
        needed.extend(
            markings
                .split(',')
                .map(str::trim)
                .filter(|marking| !marking.is_empty() && *marking != NO_MARKINGS)
                .map(str::to_string),
        );
    }
    needed.sort();
    needed.dedup();
    if needed.is_empty() {
        return Ok(());
    }
    let lattice = db
        .get_classification_lattice(&object.namespace)?
        .unwrap_or_else(|| {
            crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                &object.namespace,
            )
        });
    let held = crate::sekai::markings::object_marking_token(object).unwrap_or_default();
    let mut uncovered = Vec::new();
    for marking in &needed {
        if held.is_empty() || !lattice.dominates(held, marking)? {
            uncovered.push(marking.as_str());
        }
    }
    if uncovered.is_empty() {
        return Ok(());
    }
    Err(format!(
        "a remediation that touches data marked {} needs a matching grant",
        uncovered.join(", ")
    ))
}

fn exposure_is_marked(exposure: &Object) -> bool {
    crate::sekai::markings::object_marking_token(exposure).is_some()
        || exposure
            .properties
            .get("reachable_markings")
            .is_some_and(|markings| {
                markings
                    .split(',')
                    .map(str::trim)
                    .any(|marking| !marking.is_empty() && marking != NO_MARKINGS)
            })
}

fn remediation_identity(object: &Object, controls: &[(String, String)]) -> String {
    let payload = serde_json::json!([
        object.properties.get("exposure_id"),
        object.properties.get("patch_ref"),
        object.properties.get("rollout_ref"),
        controls,
    ]);
    format!(
        "remediation:{:x}",
        Sha256::digest(payload.to_string().as_bytes())
    )
}

fn mitigation_identity(remediation_id: &str, control: &str, target: &str) -> String {
    format!(
        "mitigation:{:x}",
        Sha256::digest(format!("{remediation_id}:{control}:{target}").as_bytes())
    )
}

fn required<'a>(object: &'a Object, property: &str) -> Result<&'a str, String> {
    object
        .properties
        .get(property)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{property} is required"))
}

fn string_param<'a>(parameters: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    parameters
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn truthy(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(true)) => true,
        Some(serde_json::Value::String(value)) => value == "true",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_instance::DECISION_GRANT;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmissionError, ActionInstanceDecisionRequest,
    };
    use crate::sekai::action_object_mutation::{ParkedGrant, PlannedObjectMutation};
    use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
    use crate::sekai::object_security::PrincipalPolicyContext;
    use crate::sekai::security_package::{
        ACTION_DISPOSITION_RECORD, ACTION_DISPOSITION_SUPERSEDE, ACTION_EXPOSURE, ACTION_FINDING,
        CERTIFICATION_ID, DISPOSITION_ACCEPT_RISK, install,
    };
    use crate::sekai::write_freeze::{MODE_BLOCK_AGENT_ACTIONS, freeze_reason, write_check};
    use serde_json::{Value, json};

    const NAMESPACE: &str = "ops";
    const ACTOR: &str = "reviewer";
    const APPROVER: &str = "approver";
    const ONTOLOGY_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TARGET_TYPE: &str = "docs.publish";

    fn installed() -> RuntimeDb {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        install_target_type(&runtime, NAMESPACE);
        runtime
    }

    fn request(type_id: &str, parameters: &Value, key: &str) -> ActionInstanceAdmissionRequest {
        request_in(NAMESPACE, type_id, parameters, key)
    }

    fn request_in(
        namespace: &str,
        type_id: &str,
        parameters: &Value,
        key: &str,
    ) -> ActionInstanceAdmissionRequest {
        ActionInstanceAdmissionRequest {
            agent_turn: None,
            namespace: namespace.into(),
            type_id: type_id.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters.to_string(),
            idempotency_key: key.into(),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: ONTOLOGY_DIGEST.into(),
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

    fn admit(
        runtime: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
    ) -> Result<
        crate::sekai::action_instance_admission::ActionInstanceAdmissionOutcome,
        ActionInstanceAdmissionError,
    > {
        ActionInstanceAdmission::new(runtime, None).admit(
            request(type_id, &parameters, key),
            ACTOR,
            2_000,
        )
    }

    fn grant(
        runtime: &RuntimeDb,
        instance_id: &str,
    ) -> Result<
        crate::sekai::action_instance_admission::ActionInstanceAdmissionOutcome,
        ActionInstanceAdmissionError,
    > {
        ActionInstanceAdmission::new(runtime, None).decide(
            ActionInstanceDecisionRequest {
                instance_id: instance_id.into(),
                decision: DECISION_GRANT.into(),
                reason: "contain".into(),
                decider_principals: vec![APPROVER.into()],
                decider_is_namespace_admin: true,
                delegating_actor: None,
                execution_claim: None,
            },
            APPROVER,
            3_000,
        )
    }

    fn with_exposure() -> RuntimeDb {
        let runtime = installed();
        admit(
            &runtime,
            ACTION_FINDING,
            json!({
                "object_id": "f-1",
                "source": "scanner",
                "component": "openssl",
                "version_range": "<3.0.8",
                "problem_signature": "sig-1",
                "reported_severity": "high"
            }),
            "f",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_EXPOSURE,
            json!({
                "object_id": "e-1",
                "finding_id": "f-1",
                "release": "api@1.4.0",
                "environment": "prod",
                "verdict": "unknown"
            }),
            "e",
        )
        .unwrap();
        runtime
    }

    fn propose_freeze() -> Value {
        json!({
            "object_id": "r-1",
            "exposure_id": "e-1",
            "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
            "asset_criticality": "low"
        })
    }

    fn apply_freeze_params() -> Value {
        json!({
            "object_id": "m-1",
            "remediation_id": "r-1",
            "control": CONTROL_FREEZE,
            "target": TARGET_TYPE,
            "state": STATE_APPLIED
        })
    }

    fn failed_precondition<T: std::fmt::Debug>(
        outcome: Result<T, ActionInstanceAdmissionError>,
    ) -> String {
        match outcome {
            Err(ActionInstanceAdmissionError::FailedPrecondition(message)) => message,
            other => panic!("expected FailedPrecondition, got {other:?}"),
        }
    }

    fn confidential_gate() -> crate::sekai::action_instance_admission::MarkingGate {
        crate::sekai::action_instance_admission::MarkingGate::new(move |marking| {
            crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                NAMESPACE,
            )
            .dominates("confidential", marking)
        })
    }

    fn admit_confidential(
        runtime: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
    ) -> Result<
        crate::sekai::action_instance_admission::ActionInstanceAdmissionOutcome,
        ActionInstanceAdmissionError,
    > {
        let mut admission = request(type_id, &parameters, key);
        admission.marking_gate = confidential_gate();
        ActionInstanceAdmission::new(runtime, None).admit(admission, ACTOR, 2_000)
    }

    fn admit_in(
        runtime: &RuntimeDb,
        namespace: &str,
        type_id: &str,
        parameters: Value,
        key: &str,
    ) -> Result<
        crate::sekai::action_instance_admission::ActionInstanceAdmissionOutcome,
        ActionInstanceAdmissionError,
    > {
        ActionInstanceAdmission::new(runtime, None).admit(
            request_in(namespace, type_id, &parameters, key),
            ACTOR,
            2_000,
        )
    }

    fn publish(
        runtime: &RuntimeDb,
        object_id: &str,
        key: &str,
    ) -> Result<(), ActionInstanceAdmissionError> {
        publish_in(runtime, NAMESPACE, object_id, key)
    }

    fn publish_in(
        runtime: &RuntimeDb,
        namespace: &str,
        object_id: &str,
        key: &str,
    ) -> Result<(), ActionInstanceAdmissionError> {
        ActionInstanceAdmission::new(runtime, None)
            .admit(
                ActionInstanceAdmissionRequest {
                    version: "1".into(),
                    ..request_in(
                        namespace,
                        TARGET_TYPE,
                        &json!({"object_id": object_id}),
                        key,
                    )
                },
                ACTOR,
                4_000,
            )
            .map(|_| ())
    }

    fn install_target_type(runtime: &RuntimeDb, namespace: &str) {
        runtime
            .put_governed_action_type(
                GovernedActionType {
                    namespace: namespace.into(),
                    type_id: TARGET_TYPE.into(),
                    version: "1".into(),
                    description: "publish a document".into(),
                    parameter_schema_json: r#"{"type":"object","additionalProperties":false,"properties":{"object_id":{"type":"string"}},"required":["object_id"]}"#.into(),
                    allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                    enabled: true,
                    ..Default::default()
                },
                ACTOR,
                1_000,
            )
            .unwrap();
    }

    /// A freeze on one Action type takes effect at the next admission after
    /// approval and is lifted by an approved follow-up Action.
    #[test]
    fn freeze_takes_effect_after_approval_and_lifts() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        assert!(runtime.get_object("r-1").unwrap().is_some());

        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        assert_eq!(parked.instance.status, STATUS_PARKED);
        assert!(runtime.get_object("m-1").unwrap().is_none());
        publish(&runtime, "doc-open", "doc-open").unwrap();

        grant(&runtime, &parked.instance.instance_id).unwrap();
        let mitigation = runtime.get_object("m-1").unwrap().unwrap();
        assert_eq!(mitigation.properties["state"], STATE_APPLIED);
        let blocked = publish(&runtime, "doc-frozen", "doc-frozen").unwrap_err();
        assert!(
            matches!(
                blocked,
                ActionInstanceAdmissionError::FailedPrecondition(ref reason)
                    if reason.contains("write freeze") && reason.contains(TARGET_TYPE)
            ),
            "{blocked:?}"
        );
        assert!(
            freeze_reason(&runtime, write_check(NAMESPACE, "", ACTOR, TARGET_TYPE),)
                .unwrap()
                .is_some()
        );

        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        assert_eq!(lift.instance.status, STATUS_PARKED);
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_APPLIED
        );
        grant(&runtime, &lift.instance.instance_id).unwrap();
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_LIFTED
        );
        publish(&runtime, "doc-after", "doc-after").unwrap();
    }

    /// Enable-before-persist must not leave a freeze when the object never lands.
    #[test]
    fn rollback_clears_a_freeze_that_never_landed() {
        let runtime = installed();
        let object = Object {
            id: "m-1".into(),
            kind: KIND_MITIGATION.into(),
            name: "m-1".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("control".into(), CONTROL_FREEZE.into()),
                ("target".into(), TARGET_TYPE.into()),
                ("state".into(), STATE_APPLIED.into()),
            ]),
            created: 0,
            updated: 0,
        };
        enable_applied_freeze(&runtime, &object, 2_000).unwrap();
        publish(&runtime, "doc-frozen", "doc-frozen").unwrap_err();
        rollback_unapplied_freeze(&runtime, &object, 2_001).unwrap();
        publish(&runtime, "doc-open", "doc-open").unwrap();
        assert!(
            freeze_reason(&runtime, write_check(NAMESPACE, "", ACTOR, TARGET_TYPE),)
                .unwrap()
                .is_none()
        );
    }

    /// Enable-before-persist on a parked grant that does not apply must not
    /// leave the target Action type frozen.
    #[test]
    fn stale_parked_freeze_apply_does_not_leave_a_freeze() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        assert_eq!(parked.instance.status, STATUS_PARKED);
        let mut granted = parked.instance.clone();
        granted.status = STATUS_ADMITTED.into();
        let object = Object {
            id: "m-1".into(),
            kind: KIND_MITIGATION.into(),
            name: "m-1".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("remediation_id".into(), "r-1".into()),
                ("control".into(), CONTROL_FREEZE.into()),
                ("target".into(), TARGET_TYPE.into()),
                ("state".into(), STATE_APPLIED.into()),
            ]),
            created: 0,
            updated: 0,
        };
        let outcome = crate::sekai::action_object_mutation::grant_parked(
            &runtime,
            Some(PlannedObjectMutation::Create {
                object,
                references: Vec::new(),
            }),
            &granted,
            "m-1",
            "stale-digest",
            ACTOR,
            None,
            3_000,
        )
        .unwrap();
        assert!(matches!(outcome, ParkedGrant::Stale));
        assert!(runtime.get_object("m-1").unwrap().is_none());
        publish(&runtime, "doc-after-stale", "doc-after-stale").unwrap();
        assert!(
            freeze_reason(&runtime, write_check(NAMESPACE, "", ACTOR, TARGET_TYPE),)
                .unwrap()
                .is_none()
        );
    }

    /// A second grant of an already-landed freeze apply must replay, not
    /// roll back the freeze the first grant enabled.
    #[test]
    fn concurrent_parked_freeze_grant_replay_keeps_a_landed_apply() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        let first = grant(&runtime, &parked.instance.instance_id).unwrap();
        assert_eq!(first.instance.status, STATUS_ADMITTED);
        let replay = grant(&runtime, &parked.instance.instance_id).unwrap();
        assert_eq!(replay.instance.status, STATUS_ADMITTED);
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_APPLIED
        );
        publish(&runtime, "doc-replay", "doc-replay").unwrap_err();
    }

    /// Two parked applies of the same control can both pass plan-time identity
    /// checks. The second persist fails the unique index after stealing the
    /// freeze reason; rollback must return the row to the landed apply.
    #[test]
    fn unique_mitigation_collision_rolls_back_a_stolen_freeze() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let first = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        let second = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-2",
                "remediation_id": "r-1",
                "control": CONTROL_FREEZE,
                "target": TARGET_TYPE,
                "state": STATE_APPLIED
            }),
            "m-2",
        )
        .unwrap();
        grant(&runtime, &first.instance.instance_id).unwrap();
        let identity = runtime.get_object("m-1").unwrap().unwrap().external_id;
        let mut granted = second.instance.clone();
        granted.status = STATUS_ADMITTED.into();
        let object = Object {
            id: "m-2".into(),
            kind: KIND_MITIGATION.into(),
            name: "m-2".into(),
            namespace: NAMESPACE.into(),
            external_id: identity,
            properties: std::collections::HashMap::from([
                ("remediation_id".into(), "r-1".into()),
                ("control".into(), CONTROL_FREEZE.into()),
                ("target".into(), TARGET_TYPE.into()),
                ("state".into(), STATE_APPLIED.into()),
            ]),
            created: 0,
            updated: 0,
        };
        match crate::sekai::action_object_mutation::grant_parked(
            &runtime,
            Some(PlannedObjectMutation::Create {
                object,
                references: Vec::new(),
            }),
            &granted,
            "m-2",
            &second.instance.parked_object_digest,
            ACTOR,
            None,
            3_000,
        ) {
            Err(crate::sekai::action_object_mutation::ActionObjectMutationError::Internal(_)) => {}
            Err(_) => panic!("expected Internal unique collision"),
            Ok(_) => panic!("expected Internal unique collision, grant succeeded"),
        }
        assert!(runtime.get_object("m-2").unwrap().is_none());
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_APPLIED
        );
        let freeze = runtime
            .list_write_freezes()
            .unwrap()
            .into_iter()
            .find(|freeze| freeze.scope_value == TARGET_TYPE)
            .unwrap();
        assert!(freeze.enabled);
        assert_eq!(freeze.reason, freeze_reason_for("m-1"));
        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        publish(&runtime, "doc-after-collision", "doc-after-collision").unwrap();
    }

    /// NotParked rolls the grant transaction back. The freeze was enabled
    /// outside that transaction, so rollback must lift it when no object landed.
    #[test]
    fn not_parked_grant_rolls_back_an_unlanded_freeze() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        let mut granted = parked.instance.clone();
        granted.instance_id = "missing".into();
        granted.status = STATUS_ADMITTED.into();
        let object = Object {
            id: "m-1".into(),
            kind: KIND_MITIGATION.into(),
            name: "m-1".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("remediation_id".into(), "r-1".into()),
                ("control".into(), CONTROL_FREEZE.into()),
                ("target".into(), TARGET_TYPE.into()),
                ("state".into(), STATE_APPLIED.into()),
            ]),
            created: 0,
            updated: 0,
        };
        let outcome = crate::sekai::action_object_mutation::grant_parked(
            &runtime,
            Some(PlannedObjectMutation::Create {
                object,
                references: Vec::new(),
            }),
            &granted,
            "m-1",
            "",
            ACTOR,
            None,
            3_000,
        )
        .unwrap();
        assert!(matches!(outcome, ParkedGrant::NotParked));
        assert!(runtime.get_object("m-1").unwrap().is_none());
        publish(&runtime, "doc-after-not-parked", "doc-after-not-parked").unwrap();
        assert!(
            freeze_reason(&runtime, write_check(NAMESPACE, "", ACTOR, TARGET_TYPE),)
                .unwrap()
                .is_none()
        );
    }

    /// A second apply claims the freeze row so lifting the current owner
    /// cannot drop containment while that apply is still in flight.
    #[test]
    fn lifting_the_owner_keeps_an_in_flight_apply_claimed_freeze() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-2",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-2",
                "asset_criticality": "low"
            }),
            "r-2",
        )
        .unwrap();
        let first = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &first.instance.instance_id).unwrap();
        let in_flight = Object {
            id: "m-2".into(),
            kind: KIND_MITIGATION.into(),
            name: "m-2".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("remediation_id".into(), "r-2".into()),
                ("control".into(), CONTROL_FREEZE.into()),
                ("target".into(), TARGET_TYPE.into()),
                ("state".into(), STATE_APPLIED.into()),
            ]),
            created: 0,
            updated: 0,
        };
        enable_applied_freeze(&runtime, &in_flight, 3_000).unwrap();
        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        publish(&runtime, "doc-in-flight", "doc-in-flight").unwrap_err();
        let freeze = runtime
            .list_write_freezes()
            .unwrap()
            .into_iter()
            .find(|freeze| freeze.scope_value == TARGET_TYPE)
            .unwrap();
        assert!(freeze.enabled);
        assert_eq!(freeze.reason, freeze_reason_for("m-2"));
        rollback_unapplied_freeze(&runtime, &in_flight, 3_001).unwrap();
        publish(&runtime, "doc-after-in-flight", "doc-after-in-flight").unwrap();
    }

    /// Replay of a landed apply must not take the freeze reason back from an
    /// in-flight apply that already claimed the row.
    #[test]
    fn admission_replay_of_landed_apply_does_not_steal_an_in_flight_freeze() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-2",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-2",
                "asset_criticality": "low"
            }),
            "r-2",
        )
        .unwrap();
        let first = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &first.instance.instance_id).unwrap();
        let in_flight = Object {
            id: "m-2".into(),
            kind: KIND_MITIGATION.into(),
            name: "m-2".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("remediation_id".into(), "r-2".into()),
                ("control".into(), CONTROL_FREEZE.into()),
                ("target".into(), TARGET_TYPE.into()),
                ("state".into(), STATE_APPLIED.into()),
            ]),
            created: 0,
            updated: 0,
        };
        enable_applied_freeze(&runtime, &in_flight, 3_000).unwrap();
        let landed = runtime.get_object("m-1").unwrap().unwrap();
        complete_object_write(&runtime, &landed, ACTOR, 3_500);
        let freeze = runtime
            .list_write_freezes()
            .unwrap()
            .into_iter()
            .find(|freeze| freeze.scope_value == TARGET_TYPE)
            .unwrap();
        assert!(freeze.enabled);
        assert_eq!(freeze.reason, freeze_reason_for("m-2"));
        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        publish(&runtime, "doc-replay-in-flight", "doc-replay-in-flight").unwrap_err();
        let freeze = runtime
            .list_write_freezes()
            .unwrap()
            .into_iter()
            .find(|freeze| freeze.scope_value == TARGET_TYPE)
            .unwrap();
        assert!(freeze.enabled);
        assert_eq!(freeze.reason, freeze_reason_for("m-2"));
        rollback_unapplied_freeze(&runtime, &in_flight, 3_001).unwrap();
        publish(&runtime, "doc-after-replay", "doc-after-replay").unwrap();
    }

    /// Lifting one freeze leaves every other applied freeze on that Action type.
    #[test]
    fn lifting_one_freeze_keeps_another_applied_freeze() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-1",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-1",
                "asset_criticality": "low"
            }),
            "r-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-2",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-2",
                "asset_criticality": "low"
            }),
            "r-2",
        )
        .unwrap();
        let first = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &first.instance.instance_id).unwrap();
        let second = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-2",
                "remediation_id": "r-2",
                "control": CONTROL_FREEZE,
                "target": TARGET_TYPE,
                "state": STATE_APPLIED
            }),
            "m-2",
        )
        .unwrap();
        grant(&runtime, &second.instance.instance_id).unwrap();

        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        publish(&runtime, "doc-still-frozen", "doc-still-frozen").unwrap_err();

        let lift_rest = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-2", "state": STATE_LIFTED}),
            "lift-2",
        )
        .unwrap();
        grant(&runtime, &lift_rest.instance.instance_id).unwrap();
        publish(&runtime, "doc-after-both", "doc-after-both").unwrap();
    }

    /// SCOPE_ACTION freeze is cluster-global. Lifting the last freeze in one
    /// namespace leaves every other namespace's applied freeze in force.
    #[test]
    fn lifting_a_freeze_keeps_another_namespaces_applied_freeze() {
        const OTHER: &str = "other";
        let runtime = with_exposure();
        install(&runtime, OTHER, ACTOR, 1_000).unwrap();
        install_target_type(&runtime, OTHER);
        admit_in(
            &runtime,
            OTHER,
            ACTION_FINDING,
            json!({
                "object_id": "f-other",
                "source": "scanner",
                "component": "openssl",
                "version_range": "<3.0.8",
                "problem_signature": "sig-other",
                "reported_severity": "high"
            }),
            "f-other",
        )
        .unwrap();
        admit_in(
            &runtime,
            OTHER,
            ACTION_EXPOSURE,
            json!({
                "object_id": "e-other",
                "finding_id": "f-other",
                "release": "api@1.4.0",
                "environment": "prod",
                "verdict": "unknown"
            }),
            "e-other",
        )
        .unwrap();

        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        admit_in(
            &runtime,
            OTHER,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-other",
                "exposure_id": "e-other",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "asset_criticality": "low"
            }),
            "r-other",
        )
        .unwrap();
        let first = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &first.instance.instance_id).unwrap();
        let second = admit_in(
            &runtime,
            OTHER,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-other",
                "remediation_id": "r-other",
                "control": CONTROL_FREEZE,
                "target": TARGET_TYPE,
                "state": STATE_APPLIED
            }),
            "m-other",
        )
        .unwrap();
        grant(&runtime, &second.instance.instance_id).unwrap();

        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        publish(&runtime, "doc-ops-still-frozen", "doc-ops-still-frozen").unwrap_err();
        publish_in(
            &runtime,
            OTHER,
            "doc-other-still-frozen",
            "doc-other-still-frozen",
        )
        .unwrap_err();

        let lift_rest = admit_in(
            &runtime,
            OTHER,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-other", "state": STATE_LIFTED}),
            "lift-other",
        )
        .unwrap();
        grant(&runtime, &lift_rest.instance.instance_id).unwrap();
        publish(&runtime, "doc-ops-after", "doc-ops-after").unwrap();
        publish_in(&runtime, OTHER, "doc-other-after", "doc-other-after").unwrap();
    }

    /// Lifting a security freeze does not disable an unrelated freeze on the
    /// same Action type.
    #[test]
    fn lifting_a_security_freeze_leaves_an_operator_freeze() {
        let runtime = with_exposure();
        runtime
            .set_write_freeze(&WriteFreeze {
                scope_kind: SCOPE_ACTION.into(),
                scope_value: TARGET_TYPE.into(),
                mode: MODE_BLOCK_WRITES.into(),
                reason: "operator freeze".into(),
                enabled: true,
                updated_ms: 1_500,
            })
            .unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &parked.instance.instance_id).unwrap();
        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        publish(&runtime, "doc-operator", "doc-operator").unwrap_err();
        let freeze = runtime
            .list_write_freezes()
            .unwrap()
            .into_iter()
            .find(|freeze| freeze.scope_value == TARGET_TYPE)
            .unwrap();
        assert!(freeze.enabled);
        assert_eq!(freeze.reason, "operator freeze");
    }

    /// An operator freeze that only blocks agents is raised to block writes.
    #[test]
    fn applying_a_freeze_raises_an_agent_only_operator_freeze() {
        let runtime = with_exposure();
        runtime
            .set_write_freeze(&WriteFreeze {
                scope_kind: SCOPE_ACTION.into(),
                scope_value: TARGET_TYPE.into(),
                mode: MODE_BLOCK_AGENT_ACTIONS.into(),
                reason: "operator freeze".into(),
                enabled: true,
                updated_ms: 1_500,
            })
            .unwrap();
        publish(&runtime, "doc-agent-only", "doc-agent-only").unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &parked.instance.instance_id).unwrap();
        publish(&runtime, "doc-raised", "doc-raised").unwrap_err();
        let freeze = runtime
            .list_write_freezes()
            .unwrap()
            .into_iter()
            .find(|freeze| freeze.scope_value == TARGET_TYPE)
            .unwrap();
        assert!(freeze.enabled);
        assert_eq!(freeze.mode, MODE_BLOCK_WRITES);
        assert!(
            freeze.reason.starts_with("security mitigation "),
            "{}",
            freeze.reason
        );
        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-1", "state": STATE_LIFTED}),
            "lift-1",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        publish(&runtime, "doc-after-raise", "doc-after-raise").unwrap();
    }

    /// Unfreezing an overlapping operator freeze is refused while a freeze
    /// mitigation is still applied.
    #[test]
    fn operator_unfreeze_is_refused_while_a_security_freeze_is_applied() {
        let runtime = with_exposure();
        runtime
            .set_write_freeze(&WriteFreeze {
                scope_kind: SCOPE_ACTION.into(),
                scope_value: TARGET_TYPE.into(),
                mode: MODE_BLOCK_WRITES.into(),
                reason: "operator freeze".into(),
                enabled: true,
                updated_ms: 1_500,
            })
            .unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &parked.instance.instance_id).unwrap();
        let error = runtime
            .set_write_freeze(&WriteFreeze {
                scope_kind: SCOPE_ACTION.into(),
                scope_value: TARGET_TYPE.into(),
                mode: MODE_BLOCK_WRITES.into(),
                reason: "operator freeze".into(),
                enabled: false,
                updated_ms: 4_000,
            })
            .unwrap_err();
        assert!(error.contains("held by security mitigation m-1"), "{error}");
        publish(&runtime, "doc-still-frozen", "doc-still-frozen").unwrap_err();
        let freeze = runtime
            .list_write_freezes()
            .unwrap()
            .into_iter()
            .find(|freeze| freeze.scope_value == TARGET_TYPE)
            .unwrap();
        assert!(freeze.enabled);
        assert_eq!(freeze.reason, "operator freeze");
    }

    /// A lift proposal does not drop containment. Operator unfreeze stays
    /// refused until `security.mitigation.lift` is granted.
    #[test]
    fn operator_unfreeze_is_refused_while_a_freeze_lift_is_proposed() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &parked.instance.instance_id).unwrap();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            json!({
                "object_id": "d-1",
                "exposure_id": "e-1",
                "disposition": DISPOSITION_FIXED,
                "dependency_closure_digest": "sha256:closure",
                "release_digest": "sha256:release",
                "configuration_digest": "sha256:config",
                "advisory_revision": "GHSA-1:3"
            }),
            "d-1",
        )
        .unwrap();
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_LIFT_PROPOSED
        );
        let error = runtime
            .set_write_freeze(&WriteFreeze {
                scope_kind: SCOPE_ACTION.into(),
                scope_value: TARGET_TYPE.into(),
                mode: MODE_BLOCK_WRITES.into(),
                reason: "operator freeze".into(),
                enabled: false,
                updated_ms: 4_000,
            })
            .unwrap_err();
        assert!(error.contains("held by security mitigation m-1"), "{error}");
        publish(&runtime, "doc-still-frozen", "doc-proposed").unwrap_err();
    }

    /// Lifting one freeze leaves a lift-proposed freeze on that Action type.
    #[test]
    fn lifting_one_freeze_keeps_a_lift_proposed_freeze() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-1",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-1",
                "asset_criticality": "low"
            }),
            "r-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-2",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-2",
                "asset_criticality": "low"
            }),
            "r-2",
        )
        .unwrap();
        let first = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &first.instance.instance_id).unwrap();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            json!({
                "object_id": "d-1",
                "exposure_id": "e-1",
                "disposition": DISPOSITION_FIXED,
                "dependency_closure_digest": "sha256:closure",
                "release_digest": "sha256:release",
                "configuration_digest": "sha256:config",
                "advisory_revision": "GHSA-1:3"
            }),
            "d-1",
        )
        .unwrap();
        let second = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-2",
                "remediation_id": "r-2",
                "control": CONTROL_FREEZE,
                "target": TARGET_TYPE,
                "state": STATE_APPLIED
            }),
            "m-2",
        )
        .unwrap();
        grant(&runtime, &second.instance.instance_id).unwrap();
        let lift = admit(
            &runtime,
            ACTION_MITIGATION_LIFT,
            json!({"object_id": "m-2", "state": STATE_LIFTED}),
            "lift-2",
        )
        .unwrap();
        grant(&runtime, &lift.instance.instance_id).unwrap();
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_LIFT_PROPOSED
        );
        publish(&runtime, "doc-still-proposed", "doc-still-proposed").unwrap_err();
    }

    /// A weaker enabled freeze is refused while a freeze mitigation is applied.
    #[test]
    fn operator_weaken_is_refused_while_a_security_freeze_is_applied() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &parked.instance.instance_id).unwrap();
        let error = runtime
            .set_write_freeze(&WriteFreeze {
                scope_kind: SCOPE_ACTION.into(),
                scope_value: TARGET_TYPE.into(),
                mode: MODE_BLOCK_AGENT_ACTIONS.into(),
                reason: "operator freeze".into(),
                enabled: true,
                updated_ms: 4_000,
            })
            .unwrap_err();
        assert!(error.contains("held by security mitigation m-1"), "{error}");
        publish(&runtime, "doc-not-weakened", "doc-not-weakened").unwrap_err();
    }

    /// Apply snapshots the exposure through the remediation before it stamps
    /// exposure_id, so a concurrent marking raise refuses the write.
    #[test]
    fn mitigation_apply_fences_the_exposure_through_the_remediation() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let planned = Object {
            id: "m-1".into(),
            kind: KIND_MITIGATION.into(),
            name: "m-1".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("remediation_id".into(), "r-1".into()),
                ("control".into(), CONTROL_FREEZE.into()),
                ("target".into(), TARGET_TYPE.into()),
                ("state".into(), STATE_APPLIED.into()),
            ]),
            created: 0,
            updated: 0,
        };
        let refs = references(&runtime, &planned).unwrap();
        assert!(
            refs.iter()
                .any(|item| matches!(item, PlanReference::Present(object) if object.id == "e-1")),
            "{refs:?}"
        );
    }

    /// A missing exposure cannot be evaluated for marked-data parking, so
    /// the proposal parks instead of auto-admitting.
    #[test]
    fn missing_exposure_parks_a_remediation_proposal() {
        let runtime = installed();
        let parked = admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-missing",
                "exposure_id": "e-missing",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "asset_criticality": "low"
            }),
            "r-missing",
        )
        .unwrap();
        assert_eq!(parked.instance.status, STATUS_PARKED);
        assert!(runtime.get_object("r-missing").unwrap().is_none());
    }

    /// A remediation that touches marked data cannot be approved by a
    /// principal without the matching grant.
    #[test]
    fn marked_remediation_needs_the_matching_grant() {
        let runtime = with_exposure();
        let mut exposure = runtime.get_object("e-1").unwrap().unwrap();
        exposure
            .properties
            .insert("reachable_markings".into(), "confidential".into());
        runtime.update_object(&exposure).unwrap();

        let mut propose = propose_freeze();
        let unmarked = admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose.clone(),
            "r-marked",
        )
        .unwrap();
        assert_eq!(unmarked.instance.status, STATUS_PARKED);
        let message = failed_precondition(grant(&runtime, &unmarked.instance.instance_id));
        assert!(message.contains("confidential"), "{message}");
        assert!(runtime.get_object("r-1").unwrap().is_none());

        propose["access_marking"] = "confidential".into();
        let denied = {
            let mut admission = request(ACTION_REMEDIATION_PROPOSE, &propose, "r-internal");
            admission.marking_gate = crate::sekai::action_instance_admission::MarkingGate::new(
                move |marking| {
                    crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                        NAMESPACE,
                    )
                    .dominates("internal", marking)
                },
            );
            ActionInstanceAdmission::new(&runtime, None).admit(admission, ACTOR, 2_000)
        };
        assert!(
            matches!(
                denied,
                Err(ActionInstanceAdmissionError::PermissionDenied(_))
            ),
            "{denied:?}"
        );
        assert!(runtime.get_object("r-1").unwrap().is_none());

        let mut admission = request(ACTION_REMEDIATION_PROPOSE, &propose, "r-cleared");
        admission.marking_gate = crate::sekai::action_instance_admission::MarkingGate::new(
            move |marking| {
                crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                    NAMESPACE,
                )
                .dominates("confidential", marking)
            },
        );
        let parked = ActionInstanceAdmission::new(&runtime, None)
            .admit(admission, ACTOR, 2_000)
            .unwrap();
        assert_eq!(parked.instance.status, STATUS_PARKED);
    }

    /// A gateway tool-disable is applied only after the decision, and the
    /// receipt chain links finding, exposure, decision and gateway audit.
    #[test]
    fn gateway_tool_disable_applies_after_decision_with_receipt_chain() {
        let runtime = with_exposure();
        let early = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-gw",
                "remediation_id": "r-gw",
                "control": CONTROL_GATEWAY_TOOL,
                "target": "shell",
                "state": STATE_APPLIED
            }),
            "gw-early",
        )
        .unwrap();
        assert_eq!(early.instance.status, STATUS_PARKED);
        assert!(runtime.get_object("m-gw").unwrap().is_none());
        let too_soon = failed_precondition(grant(&runtime, &early.instance.instance_id));
        assert!(
            too_soon.contains("not found") && too_soon.contains("after the plan is decided"),
            "{too_soon}"
        );

        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-gw",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_GATEWAY_TOOL}:shell"),
                "asset_criticality": "low"
            }),
            "r-gw",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-gw",
                "remediation_id": "r-gw",
                "control": CONTROL_GATEWAY_TOOL,
                "target": "shell",
                "state": STATE_APPLIED
            }),
            "gw-apply",
        )
        .unwrap();
        assert_eq!(parked.instance.status, STATUS_PARKED);
        assert!(runtime.get_object("m-gw").unwrap().is_none());

        let granted = grant(&runtime, &parked.instance.instance_id).unwrap();
        let mitigation = runtime.get_object("m-gw").unwrap().unwrap();
        assert_eq!(mitigation.properties["state"], STATE_APPLIED);
        assert_eq!(mitigation.properties["finding_id"], "f-1");
        assert_eq!(mitigation.properties["exposure_id"], "e-1");
        assert_eq!(
            mitigation.properties["gateway_audit"],
            GATEWAY_AUDIT_PENDING
        );
        let receipt = runtime
            .get_operation_receipt(&granted.instance.operation_id)
            .unwrap()
            .unwrap();
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == sekai_domain::receipt::ReceiptEventKind::IntentRecorded)
            .unwrap();
        assert_eq!(
            intent.attributes.get("finding_id").map(String::as_str),
            Some("f-1")
        );
        assert_eq!(
            intent.attributes.get("exposure_id").map(String::as_str),
            Some("e-1")
        );
        assert_eq!(
            intent.attributes.get("decision").map(String::as_str),
            Some(granted.instance.operation_id.as_str())
        );
        assert_eq!(
            intent.attributes.get("gateway_audit").map(String::as_str),
            Some(GATEWAY_AUDIT_PENDING)
        );
    }

    /// A marking raise is applied only after the decision, and the receipt
    /// chain records the pending lattice audit the same way gateway controls do.
    #[test]
    fn marking_raise_applies_with_pending_audit() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-mark",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_MARKING_RAISE}:confidential"),
                "asset_criticality": "low"
            }),
            "r-mark",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-mark",
                "remediation_id": "r-mark",
                "control": CONTROL_MARKING_RAISE,
                "target": "confidential",
                "state": STATE_APPLIED
            }),
            "mark-apply",
        )
        .unwrap();
        assert_eq!(parked.instance.status, STATUS_PARKED);
        assert!(runtime.get_object("m-mark").unwrap().is_none());

        let granted = grant(&runtime, &parked.instance.instance_id).unwrap();
        let mitigation = runtime.get_object("m-mark").unwrap().unwrap();
        assert_eq!(mitigation.properties["state"], STATE_APPLIED);
        assert_eq!(
            mitigation.properties["marking_audit"],
            MARKING_AUDIT_PENDING
        );
        let receipt = runtime
            .get_operation_receipt(&granted.instance.operation_id)
            .unwrap()
            .unwrap();
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == sekai_domain::receipt::ReceiptEventKind::IntentRecorded)
            .unwrap();
        assert_eq!(
            intent.attributes.get("marking_audit").map(String::as_str),
            Some(MARKING_AUDIT_PENDING)
        );
    }

    /// A fixed disposition produces a lift proposal for every active mitigation.
    #[test]
    fn fixed_disposition_proposes_lifting_active_mitigations() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            propose_freeze(),
            "r-1",
        )
        .unwrap();
        let parked = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &parked.instance.instance_id).unwrap();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            json!({
                "object_id": "d-1",
                "exposure_id": "e-1",
                "disposition": DISPOSITION_FIXED,
                "dependency_closure_digest": "sha256:closure",
                "release_digest": "sha256:release",
                "configuration_digest": "sha256:config",
                "advisory_revision": "GHSA-1:3"
            }),
            "d-1",
        )
        .unwrap();
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_LIFT_PROPOSED
        );
    }

    /// A superseded fixed disposition must not catch up lift proposals.
    #[test]
    fn superseded_fixed_disposition_does_not_propose_lifts() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-1",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-1",
                "asset_criticality": "low"
            }),
            "r-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_REMEDIATION_PROPOSE,
            json!({
                "object_id": "r-2",
                "exposure_id": "e-1",
                "controls": format!("{CONTROL_FREEZE}:{TARGET_TYPE}"),
                "patch_ref": "cr-2",
                "asset_criticality": "low"
            }),
            "r-2",
        )
        .unwrap();
        let first = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            apply_freeze_params(),
            "m-1",
        )
        .unwrap();
        grant(&runtime, &first.instance.instance_id).unwrap();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            json!({
                "object_id": "d-1",
                "exposure_id": "e-1",
                "disposition": DISPOSITION_FIXED,
                "dependency_closure_digest": "sha256:closure",
                "release_digest": "sha256:release",
                "configuration_digest": "sha256:config",
                "advisory_revision": "GHSA-1:3"
            }),
            "d-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            json!({
                "object_id": "d-2",
                "exposure_id": "e-1",
                "disposition": DISPOSITION_ACCEPT_RISK,
                "supersedes": "d-1",
                "dependency_closure_digest": "sha256:closure",
                "release_digest": "sha256:release",
                "configuration_digest": "sha256:config",
                "advisory_revision": "GHSA-1:3",
                "expires_at_ms": 9_000
            }),
            "d-2",
        )
        .unwrap();
        let later = admit(
            &runtime,
            ACTION_MITIGATION_APPLY,
            json!({
                "object_id": "m-2",
                "remediation_id": "r-2",
                "control": CONTROL_FREEZE,
                "target": TARGET_TYPE,
                "state": STATE_APPLIED
            }),
            "m-2",
        )
        .unwrap();
        grant(&runtime, &later.instance.instance_id).unwrap();
        let fixed = runtime.get_object("d-1").unwrap().unwrap();
        complete_object_write(&runtime, &fixed, ACTOR, 5_000);
        assert_eq!(
            runtime.get_object("m-2").unwrap().unwrap().properties["state"],
            STATE_APPLIED
        );
    }

    /// An unmarked fixed disposition does not move a marked mitigation.
    #[test]
    fn unmarked_fixed_disposition_does_not_propose_lifting_marked_mitigations() {
        let runtime = with_exposure();
        let mut exposure = runtime.get_object("e-1").unwrap().unwrap();
        exposure
            .properties
            .insert("reachable_markings".into(), "confidential".into());
        runtime.update_object(&exposure).unwrap();

        let mut propose = propose_freeze();
        propose["access_marking"] = "confidential".into();
        let proposed =
            admit_confidential(&runtime, ACTION_REMEDIATION_PROPOSE, propose, "r-1").unwrap();
        grant(&runtime, &proposed.instance.instance_id).unwrap();

        let mut apply = apply_freeze_params();
        apply["access_marking"] = "confidential".into();
        let parked = admit_confidential(&runtime, ACTION_MITIGATION_APPLY, apply, "m-1").unwrap();
        grant(&runtime, &parked.instance.instance_id).unwrap();
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_APPLIED
        );

        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            json!({
                "object_id": "d-1",
                "exposure_id": "e-1",
                "disposition": DISPOSITION_FIXED,
                "dependency_closure_digest": "sha256:closure",
                "release_digest": "sha256:release",
                "configuration_digest": "sha256:config",
                "advisory_revision": "GHSA-1:3"
            }),
            "d-1",
        )
        .unwrap();
        assert_eq!(
            runtime.get_object("m-1").unwrap().unwrap().properties["state"],
            STATE_APPLIED
        );
    }

    #[test]
    fn certification_succeeds_the_previous_package() {
        let runtime = installed();
        let certified = crate::sekai::capability_package::get_package(
            &runtime,
            ACTOR,
            NAMESPACE,
            CERTIFICATION_ID,
        )
        .unwrap();
        assert_eq!(
            certified.certification_id,
            crate::sekai::security_package::CERTIFICATION_ID
        );
        assert!(runtime.get_object_type(KIND_REMEDIATION).unwrap().is_some());
        assert!(runtime.get_object_type(KIND_MITIGATION).unwrap().is_some());
    }
}
