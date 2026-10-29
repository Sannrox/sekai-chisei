//! Gradual agent autonomy (#1469).
//!
//! Agents start propose-only. Per agent and Action type, parked grant/deny
//! history can earn an auto-apply grant that extends a live #715 envelope.
//! Grant and revoke write Decision receipts. A rejected Action or a model
//! pin change revokes the grant. Amount/scope/time-of-day limits and
//! decision memory stay out. Parked proposes reuse the type's review queue.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_instance::{DECISION_GRANT, STATUS_DENIED};
use crate::sekai::audit::Decision;
use crate::sekai::autonomous_envelope::{self, STATUS_LIVE};

pub const STATUS_LIVE_GRANT: &str = "live";
pub const STATUS_REVOKED: &str = "revoked";
pub const REASON_ADMIN: &str = "admin";
pub const REASON_REJECTED: &str = "rejected_action";
pub const REASON_MODEL_CHANGE: &str = "model_change";
pub const REASON_ENVELOPE: &str = "envelope_not_live";
pub const ACTION_GRANT: &str = "grant_agent_autonomy";
pub const ACTION_REVOKE: &str = "revoke_agent_autonomy";
pub const POSTGRES_UNAVAILABLE: &str =
    "agent autonomy grants are unavailable on the PostgreSQL community runtime";
pub const CONCURRENT_CHANGE: &str = "agent autonomy grant changed concurrently";

pub const DEFAULT_MIN_REVIEWS: u32 = 50;
pub const DEFAULT_MIN_UNCHANGED_BPS: u32 = 9_800;
pub const DEFAULT_MAX_INCIDENTS: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutonomyThreshold {
    pub min_reviews: u32,
    pub min_unchanged_bps: u32,
    pub max_incidents: u32,
}

impl AutonomyThreshold {
    pub const fn production() -> Self {
        Self {
            min_reviews: DEFAULT_MIN_REVIEWS,
            min_unchanged_bps: DEFAULT_MIN_UNCHANGED_BPS,
            max_incidents: DEFAULT_MAX_INCIDENTS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAutonomyGrant {
    pub namespace: String,
    pub principal: String,
    pub type_id: String,
    pub status: String,
    pub envelope_id: String,
    pub model_digest: String,
    pub granted_by: String,
    pub granted_at_ms: i64,
    #[serde(default)]
    pub revoked_by: String,
    #[serde(default)]
    pub revoked_at_ms: i64,
    #[serde(default)]
    pub revoke_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutonomyOffer {
    pub namespace: String,
    pub principal: String,
    pub type_id: String,
    pub reviews: u32,
    pub approved_unchanged: u32,
    pub incidents: u32,
    pub eligible: bool,
    pub granted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionAutonomy {
    ProposeOnly,
    AutoApply { envelope_id: String },
}

#[derive(Debug, Clone, Copy)]
pub struct GrantAutoApplyRequest<'a> {
    pub actor: &'a str,
    pub namespace: &'a str,
    pub principal: &'a str,
    pub type_id: &'a str,
    pub envelope_id: &'a str,
    pub now_ms: i64,
    pub threshold: AutonomyThreshold,
}

pub fn is_agent_principal(principal: &str) -> bool {
    principal.starts_with("agent:")
}

/// Service-principal lookup errors fail closed as agent so auto-apply cannot
/// bypass propose-only when the registry is unavailable. Machine credentials
/// and delegating actors are freeze's agent-action classifier, not this
/// principal check: humans keep Allow until the actor itself is an agent.
pub fn actor_is_agent(db: &RuntimeDb, principal: &str) -> bool {
    if is_agent_principal(principal) {
        return true;
    }
    db.get_service_principal(principal)
        .map(|registration| registration.is_some())
        .unwrap_or(true)
}

pub fn measure(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    type_id: &str,
) -> Result<(u32, u32, u32), String> {
    required("namespace", namespace)?;
    required("principal", principal)?;
    required("type_id", type_id)?;
    let mut reviews = 0u32;
    let mut approved_unchanged = 0u32;
    let mut incidents = 0u32;
    let mut offset = 0usize;
    loop {
        let page = db.list_action_instances_page(namespace, Some(type_id), None, 500, offset)?;
        if page.is_empty() {
            break;
        }
        offset = offset.saturating_add(page.len());
        for instance in page {
            if instance.principal != principal {
                continue;
            }
            if instance.status == STATUS_DENIED {
                reviews = reviews.saturating_add(1);
                incidents = incidents.saturating_add(1);
            } else if instance.approval_decision == DECISION_GRANT {
                reviews = reviews.saturating_add(1);
                approved_unchanged = approved_unchanged.saturating_add(1);
            }
        }
    }
    Ok((reviews, approved_unchanged, incidents))
}

pub fn offer(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    type_id: &str,
    threshold: AutonomyThreshold,
) -> Result<AutonomyOffer, String> {
    let (reviews, approved_unchanged, incidents) = measure(db, namespace, principal, type_id)?;
    let granted = matches!(
        db.get_agent_autonomy(namespace, principal, type_id)?,
        Some(grant) if grant.status == STATUS_LIVE_GRANT
    );
    let eligible = !granted
        && reviews >= threshold.min_reviews
        && incidents <= threshold.max_incidents
        && meets_rate(approved_unchanged, reviews, threshold.min_unchanged_bps);
    Ok(AutonomyOffer {
        namespace: namespace.into(),
        principal: principal.into(),
        type_id: type_id.into(),
        reviews,
        approved_unchanged,
        incidents,
        eligible,
        granted,
    })
}

pub fn grant_auto_apply(
    db: &RuntimeDb,
    request: GrantAutoApplyRequest<'_>,
) -> Result<AgentAutonomyGrant, String> {
    required("actor", request.actor)?;
    required("namespace", request.namespace)?;
    required("principal", request.principal)?;
    required("type_id", request.type_id)?;
    required("envelope_id", request.envelope_id)?;
    require_positive(request.now_ms)?;
    if !actor_is_agent(db, request.principal) {
        return Err("auto-apply is only granted to agents".into());
    }
    let snapshot = offer(
        db,
        request.namespace,
        request.principal,
        request.type_id,
        request.threshold,
    )?;
    if snapshot.granted {
        let existing = db
            .get_agent_autonomy(request.namespace, request.principal, request.type_id)?
            .ok_or_else(|| "live auto-apply grant vanished".to_string())?;
        if existing.envelope_id == request.envelope_id {
            ensure_receipt(
                db,
                request.actor,
                ACTION_GRANT,
                "agent_autonomy_granted",
                &existing,
                request.now_ms,
            )?;
            return Ok(existing);
        }
        return Err("live auto-apply grant already exists for this Action type".into());
    }
    if !snapshot.eligible {
        return Err("agent has not earned auto-apply for this Action type".into());
    }
    let envelope = autonomous_envelope::require_live_envelope(
        db,
        request.principal,
        request.namespace,
        request.envelope_id,
    )?;
    let grant = AgentAutonomyGrant {
        namespace: request.namespace.into(),
        principal: request.principal.into(),
        type_id: request.type_id.into(),
        status: STATUS_LIVE_GRANT.into(),
        envelope_id: request.envelope_id.into(),
        model_digest: envelope.pins.model_digest,
        granted_by: request.actor.into(),
        granted_at_ms: request.now_ms,
        revoked_by: String::new(),
        revoked_at_ms: 0,
        revoke_reason: String::new(),
    };
    if let Err(error) = persist_grant(
        db,
        request.actor,
        ACTION_GRANT,
        "agent_autonomy_granted",
        &grant,
        request.now_ms,
    ) {
        if error != CONCURRENT_CHANGE {
            return Err(error);
        }
        let existing =
            db.get_agent_autonomy(request.namespace, request.principal, request.type_id)?;
        if let Some(existing) = existing {
            if existing.status == STATUS_LIVE_GRANT && existing.envelope_id == request.envelope_id {
                ensure_receipt(
                    db,
                    request.actor,
                    ACTION_GRANT,
                    "agent_autonomy_granted",
                    &existing,
                    request.now_ms,
                )?;
                return Ok(existing);
            }
            if existing.status == STATUS_LIVE_GRANT {
                return Err("live auto-apply grant already exists for this Action type".into());
            }
        }
        return Err(error);
    }
    Ok(grant)
}

pub fn revoke_auto_apply(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    principal: &str,
    type_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<Option<AgentAutonomyGrant>, String> {
    revoke_granted_by(
        db,
        actor,
        namespace,
        principal,
        type_id,
        reason,
        i64::MAX,
        now_ms,
    )
}

/// Revokes the grant only when it was issued at or before
/// `granted_by_ms`. The cutoff is checked on the grant the store's
/// compare-and-set then replaces, so a replacement issued later is never
/// revoked (#1943).
#[allow(clippy::too_many_arguments)]
fn revoke_granted_by(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    principal: &str,
    type_id: &str,
    reason: &str,
    granted_by_ms: i64,
    now_ms: i64,
) -> Result<Option<AgentAutonomyGrant>, String> {
    required("actor", actor)?;
    required("reason", reason)?;
    require_positive(now_ms)?;
    let Some(current) = db
        .get_agent_autonomy(namespace, principal, type_id)?
        .filter(|grant| grant.granted_at_ms <= granted_by_ms)
    else {
        return Ok(None);
    };
    if current.status == STATUS_REVOKED {
        ensure_revoke_receipt(db, actor, &current, now_ms)?;
        return Ok(Some(current));
    }
    let mut next = current;
    next.status = STATUS_REVOKED.into();
    next.revoked_by = actor.into();
    next.revoked_at_ms = now_ms;
    next.revoke_reason = reason.into();
    if let Err(error) = persist_grant(db, actor, ACTION_REVOKE, reason, &next, now_ms) {
        if error != CONCURRENT_CHANGE {
            return Err(error);
        }
        let current = db
            .get_agent_autonomy(namespace, principal, type_id)?
            .filter(|grant| grant.granted_at_ms <= granted_by_ms);
        let Some(grant) = current.as_ref() else {
            return Ok(None);
        };
        if grant.status == STATUS_REVOKED {
            ensure_revoke_receipt(db, actor, grant, now_ms)?;
            return Ok(current);
        }
        return Err(error);
    }
    Ok(Some(next))
}

fn grant_for_admit(
    result: Result<Option<AgentAutonomyGrant>, String>,
) -> Result<Option<AgentAutonomyGrant>, String> {
    match result {
        Err(error) if error == POSTGRES_UNAVAILABLE => Ok(None),
        other => other,
    }
}

pub fn evaluate_admission(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    type_id: &str,
    submitted_envelope_id: &str,
    now_ms: i64,
) -> Result<AdmissionAutonomy, String> {
    if !actor_is_agent(db, actor) {
        return Ok(AdmissionAutonomy::ProposeOnly);
    }
    // Grant rows are SQLite-only. PostgreSQL has no table, so admit parks
    // the agent instead of failing the submit.
    let Some(grant) = grant_for_admit(db.get_agent_autonomy(namespace, actor, type_id))? else {
        return Ok(AdmissionAutonomy::ProposeOnly);
    };
    if grant.status != STATUS_LIVE_GRANT {
        return Ok(AdmissionAutonomy::ProposeOnly);
    }
    let envelope = match autonomous_envelope::require_live_envelope(
        db,
        actor,
        namespace,
        &grant.envelope_id,
    ) {
        Ok(envelope) => envelope,
        Err(_) => {
            revoke_auto_apply(
                db,
                actor,
                namespace,
                actor,
                type_id,
                REASON_ENVELOPE,
                now_ms,
            )?;
            return Ok(AdmissionAutonomy::ProposeOnly);
        }
    };
    // The grant binds the envelope model pin. Function model_route is a
    // different identity and stays outside this slice.
    if envelope.status != STATUS_LIVE || envelope.pins.model_digest != grant.model_digest {
        revoke_auto_apply(
            db,
            actor,
            namespace,
            actor,
            type_id,
            REASON_MODEL_CHANGE,
            now_ms,
        )?;
        return Ok(AdmissionAutonomy::ProposeOnly);
    }
    if has_denial_since(db, namespace, actor, type_id, grant.granted_at_ms)? {
        revoke_auto_apply(
            db,
            actor,
            namespace,
            actor,
            type_id,
            REASON_REJECTED,
            now_ms,
        )?;
        return Ok(AdmissionAutonomy::ProposeOnly);
    }
    let submitted = submitted_envelope_id.trim();
    if !submitted.is_empty() && submitted != grant.envelope_id {
        return Ok(AdmissionAutonomy::ProposeOnly);
    }
    Ok(AdmissionAutonomy::AutoApply {
        envelope_id: grant.envelope_id,
    })
}

pub fn revoke_if_granted(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    principal: &str,
    type_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    if !actor_is_agent(db, principal) {
        return Ok(());
    }
    revoke_result(revoke_auto_apply(
        db,
        actor,
        namespace,
        principal,
        type_id,
        REASON_REJECTED,
        now_ms,
    ))
}

/// [`revoke_if_granted`] for the grant a denied admission at
/// `admitted_at_ms` rejected: a grant issued after it is a replacement and
/// is left alone, so a resumed admission never revokes it (#1943).
pub fn revoke_if_granted_before(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    principal: &str,
    type_id: &str,
    admitted_at_ms: i64,
    now_ms: i64,
) -> Result<(), String> {
    if !actor_is_agent(db, principal) {
        return Ok(());
    }
    revoke_result(revoke_granted_by(
        db,
        actor,
        namespace,
        principal,
        type_id,
        REASON_REJECTED,
        admitted_at_ms,
        now_ms,
    ))
}

fn revoke_result(result: Result<Option<AgentAutonomyGrant>, String>) -> Result<(), String> {
    match result {
        Ok(_) => Ok(()),
        Err(error) if error == POSTGRES_UNAVAILABLE => Ok(()),
        Err(error) => Err(error),
    }
}

fn has_denial_since(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    type_id: &str,
    since_ms: i64,
) -> Result<bool, String> {
    let mut offset = 0usize;
    loop {
        let page = db.list_action_instances_page(namespace, Some(type_id), None, 500, offset)?;
        if page.is_empty() {
            return Ok(false);
        }
        offset = offset.saturating_add(page.len());
        for instance in page {
            if instance.principal == principal
                && instance.status == STATUS_DENIED
                && instance.decided_at_ms >= since_ms
            {
                return Ok(true);
            }
        }
    }
}

fn ensure_revoke_receipt(
    db: &RuntimeDb,
    actor: &str,
    grant: &AgentAutonomyGrant,
    now_ms: i64,
) -> Result<(), String> {
    ensure_receipt(
        db,
        actor,
        ACTION_REVOKE,
        &grant.revoke_reason,
        grant,
        now_ms,
    )
}

fn ensure_receipt(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    reason: &str,
    grant: &AgentAutonomyGrant,
    now_ms: i64,
) -> Result<(), String> {
    let existing = db.list_decisions(&crate::sekai::audit::DecisionFilter {
        action: Some(action.into()),
        target_id: Some(grant_target(grant)),
        ..crate::sekai::audit::DecisionFilter::default()
    })?;
    if existing.is_empty() {
        record_receipt(db, actor, action, reason, grant, now_ms)?;
    }
    Ok(())
}

fn grant_target(grant: &AgentAutonomyGrant) -> String {
    format!(
        "agent-autonomy:{}:{}:{}:{}",
        grant.namespace, grant.principal, grant.type_id, grant.granted_at_ms
    )
}

fn meets_rate(approved_unchanged: u32, reviews: u32, min_unchanged_bps: u32) -> bool {
    if reviews == 0 {
        return false;
    }
    u64::from(approved_unchanged) * 10_000 >= u64::from(reviews) * u64::from(min_unchanged_bps)
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(format!("{label} must be a canonical non-empty identifier"));
    }
    Ok(())
}

fn require_positive(now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        return Err("timestamp must be positive".into());
    }
    Ok(())
}

fn persist_grant(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    reason: &str,
    grant: &AgentAutonomyGrant,
    now_ms: i64,
) -> Result<(), String> {
    db.put_agent_autonomy_with_receipt(grant, &grant_receipt(actor, action, reason, grant, now_ms))
}

fn record_receipt(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    reason: &str,
    grant: &AgentAutonomyGrant,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&grant_receipt(actor, action, reason, grant, now_ms))
}

fn grant_receipt(
    actor: &str,
    action: &str,
    reason: &str,
    grant: &AgentAutonomyGrant,
    now_ms: i64,
) -> Decision {
    Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: reason.into(),
        evidence: HashMap::from([
            ("namespace".into(), grant.namespace.clone()),
            ("principal".into(), grant.principal.clone()),
            ("type_id".into(), grant.type_id.clone()),
            ("envelope_id".into(), grant.envelope_id.clone()),
            ("model_digest".into(), grant.model_digest.clone()),
            ("status".into(), grant.status.clone()),
        ]),
        target_id: grant_target(grant),
        outcome: grant.status.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_instance::{ActionInstance, DECISION_DENY, STATUS_ADMITTED};
    use crate::sekai::audit::DecisionFilter;
    use crate::sekai::autonomous_envelope::{
        AutonomousEnvelope, AutonomousPins, ENVELOPE_CONTRACT, PROFILE_SIMULATE, PROFILE_VERSION,
        RECEIPT_CURRENT, admit_envelope, envelope_digest_for, stop_envelope,
    };
    use crate::sekai::governed_action_type::{EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType};
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    fn test_threshold() -> AutonomyThreshold {
        AutonomyThreshold {
            min_reviews: 2,
            min_unchanged_bps: 10_000,
            max_incidents: 0,
        }
    }

    fn grant_req<'a>(
        principal: &'a str,
        type_id: &'a str,
        envelope_id: &'a str,
        now_ms: i64,
    ) -> GrantAutoApplyRequest<'a> {
        GrantAutoApplyRequest {
            actor: "ops-admin",
            namespace: "acme",
            principal,
            type_id,
            envelope_id,
            now_ms,
            threshold: test_threshold(),
        }
    }

    fn setup() -> RuntimeDb {
        let db = RuntimeDb::memory();
        db.put_governed_action_type(
            GovernedActionType {
                namespace: "acme".into(),
                type_id: "dispatch".into(),
                version: "1".into(),
                description: "dispatch work".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                object_kind: String::new(),
                object_mutation: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        db
    }

    fn parked(db: &RuntimeDb, principal: &str, type_id: &str, key: &str, decision: &str, now: i64) {
        let instance = ActionInstance {
            agent_turn: None,
            instance_id: format!("inst-{key}"),
            namespace: "acme".into(),
            type_id: type_id.into(),
            version: "1".into(),
            principal: principal.into(),
            delegating_actor: None,
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            request_digest: format!("sha256:{key}"),
            idempotency_key: key.into(),
            operation_id: format!("op-{key}"),
            status: if decision == DECISION_GRANT {
                STATUS_ADMITTED.into()
            } else {
                STATUS_DENIED.into()
            },
            deny_reason: String::new(),
            evidence_submission_ids: Vec::new(),
            policy_decision: "require_approval".into(),
            budget_decision: "not_configured".into(),
            created_at_ms: now,
            decided_at_ms: now,
            system_one_fill_json: String::new(),
            parked_object_digest: String::new(),
            decided_by: "ops-admin".into(),
            approval_decision: decision.into(),
            autonomous_envelope_id: String::new(),
            review: Default::default(),
            agent_action: false,
            admission_tenant: String::new(),
            resource_tenant: String::new(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
        };
        db.put_action_instance(&instance).unwrap();
    }

    fn envelope(db: &RuntimeDb, envelope_id: &str, model_tag: u8) -> AutonomousEnvelope {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let digest = |tag: u8| format!("sha256:{tag:02x}{}", "ab".repeat(31));
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let mut envelope = AutonomousEnvelope {
            contract_version: ENVELOPE_CONTRACT.into(),
            envelope_id: envelope_id.into(),
            namespace: "acme".into(),
            owner: "agent:fixture".into(),
            adapter_id: PROFILE_SIMULATE.into(),
            adapter_version: PROFILE_VERSION.into(),
            pins: AutonomousPins {
                state_digest: digest(1),
                policy_digest: digest(2),
                model_digest: digest(model_tag),
                prompt_digest: digest(4),
                evidence_digest: digest(5),
                simulation_digest: digest(6),
                budget_digest: digest(7),
                lease_digest: digest(8),
            },
            signer_id: "signer:ops".into(),
            signer_digest: format!("sha256:{:x}", Sha256::digest(public_key)),
            public_key_hex: hex(&public_key),
            signature_hex: String::new(),
            envelope_digest: String::new(),
            receipt_digest: String::new(),
            receipt_status: RECEIPT_CURRENT.into(),
            status: STATUS_LIVE.into(),
            predecessor_id: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        envelope.envelope_digest = envelope_digest_for(&envelope).unwrap();
        envelope.signature_hex = hex(&signing_key
            .sign(envelope.envelope_digest.as_bytes())
            .to_bytes());
        admit_envelope(db, "agent:fixture", &envelope, 1_000).unwrap()
    }

    #[test]
    fn humans_are_not_agents() {
        let db = setup();
        assert!(!actor_is_agent(&db, "alice"));
        assert!(actor_is_agent(&db, "agent:fixture"));
    }

    #[test]
    fn a_postgres_unavailable_grant_lookup_stays_propose_only() {
        assert_eq!(
            grant_for_admit(Err(POSTGRES_UNAVAILABLE.into())).unwrap(),
            None
        );
    }

    #[test]
    fn a_postgres_unavailable_revoke_after_deny_is_a_noop() {
        assert_eq!(revoke_result(Err(POSTGRES_UNAVAILABLE.into())), Ok(()));
        assert!(revoke_result(Err("disk full".into())).is_err());
    }

    #[test]
    fn fixture_agent_is_offered_auto_apply_after_the_threshold() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        let short = offer(&db, "acme", "agent:fixture", "dispatch", test_threshold()).unwrap();
        assert!(!short.eligible);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        parked(&db, "alice", "dispatch", "human", DECISION_GRANT, 21);
        let ready = offer(&db, "acme", "agent:fixture", "dispatch", test_threshold()).unwrap();
        assert!(ready.eligible);
        assert_eq!(ready.reviews, 2);
        assert_eq!(ready.approved_unchanged, 2);
        assert_eq!(ready.incidents, 0);
    }

    #[test]
    fn a_denial_blocks_the_offer() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_DENY, 20);
        let snapshot = offer(&db, "acme", "agent:fixture", "dispatch", test_threshold()).unwrap();
        assert!(!snapshot.eligible);
        assert_eq!(snapshot.incidents, 1);
    }

    #[test]
    fn a_failed_grant_resume_counts_as_an_incident() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        let failed = ActionInstance {
            agent_turn: None,
            instance_id: "inst-stale".into(),
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            principal: "agent:fixture".into(),
            delegating_actor: None,
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            request_digest: "sha256:stale".into(),
            idempotency_key: "stale".into(),
            operation_id: "op-stale".into(),
            status: STATUS_DENIED.into(),
            deny_reason: "stale_on_resume".into(),
            evidence_submission_ids: Vec::new(),
            policy_decision: "require_approval".into(),
            budget_decision: "not_applicable".into(),
            created_at_ms: 20,
            decided_at_ms: 20,
            system_one_fill_json: String::new(),
            parked_object_digest: String::new(),
            decided_by: "ops-admin".into(),
            approval_decision: DECISION_GRANT.into(),
            autonomous_envelope_id: String::new(),
            review: Default::default(),
            agent_action: false,
            admission_tenant: String::new(),
            resource_tenant: String::new(),
            marking: String::new(),
            conflict: None,
            approval: None,
            offline: None,
            admission_lease: None,
            admission_ontology_digest: None,
            admission_budget_already_reserved: false,
        };
        db.put_action_instance(&failed).unwrap();
        let snapshot = offer(&db, "acme", "agent:fixture", "dispatch", test_threshold()).unwrap();
        assert!(!snapshot.eligible);
        assert_eq!(snapshot.approved_unchanged, 1);
        assert_eq!(snapshot.incidents, 1);
    }

    #[test]
    fn grant_extends_a_live_envelope_and_writes_a_receipt() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        let grant = grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        assert_eq!(grant.status, STATUS_LIVE_GRANT);
        assert!(!grant.model_digest.is_empty());
        let replay = grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 31),
        )
        .unwrap();
        assert_eq!(replay.granted_at_ms, 30);
        let receipts = db
            .list_decisions(&DecisionFilter {
                action: Some(ACTION_GRANT.into()),
                ..DecisionFilter::default()
            })
            .unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].reason, "agent_autonomy_granted");
    }

    #[test]
    fn replay_writes_a_missing_grant_receipt() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        let live = envelope(&db, "auto:dispatch", 3);
        let unaudited = AgentAutonomyGrant {
            namespace: "acme".into(),
            principal: "agent:fixture".into(),
            type_id: "dispatch".into(),
            status: STATUS_LIVE_GRANT.into(),
            envelope_id: "auto:dispatch".into(),
            model_digest: live.pins.model_digest,
            granted_by: "ops-admin".into(),
            granted_at_ms: 30,
            revoked_by: String::new(),
            revoked_at_ms: 0,
            revoke_reason: String::new(),
        };
        db.put_agent_autonomy(&unaudited).unwrap();
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 31),
        )
        .unwrap();
        let receipts = db
            .list_decisions(&DecisionFilter {
                action: Some(ACTION_GRANT.into()),
                ..DecisionFilter::default()
            })
            .unwrap();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn a_later_grant_lifecycle_writes_its_own_revoke_receipt() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        revoke_auto_apply(
            &db,
            "ops-admin",
            "acme",
            "agent:fixture",
            "dispatch",
            REASON_ADMIN,
            40,
        )
        .unwrap();
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 50),
        )
        .unwrap();
        let mut unaudited = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        unaudited.status = STATUS_REVOKED.into();
        unaudited.revoked_by = "ops-admin".into();
        unaudited.revoked_at_ms = 60;
        unaudited.revoke_reason = REASON_ADMIN.into();
        db.put_agent_autonomy(&unaudited).unwrap();
        revoke_auto_apply(
            &db,
            "ops-admin",
            "acme",
            "agent:fixture",
            "dispatch",
            REASON_ADMIN,
            70,
        )
        .unwrap();
        let receipts = db
            .list_decisions(&DecisionFilter {
                action: Some(ACTION_REVOKE.into()),
                ..DecisionFilter::default()
            })
            .unwrap();
        assert_eq!(receipts.len(), 2);
    }

    #[test]
    fn grant_refuses_humans_and_unearned_agents() {
        let db = setup();
        envelope(&db, "auto:dispatch", 3);
        let human =
            grant_auto_apply(&db, grant_req("alice", "dispatch", "auto:dispatch", 30)).unwrap_err();
        assert!(human.contains("only granted to agents"));
        let early = grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap_err();
        assert!(early.contains("has not earned"));
    }

    #[test]
    fn live_grant_auto_applies_until_revoke_or_model_change() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        assert!(matches!(
            evaluate_admission(&db, "agent:fixture", "acme", "dispatch", "", 40).unwrap(),
            AdmissionAutonomy::AutoApply { envelope_id } if envelope_id == "auto:dispatch"
        ));
        assert!(matches!(
            evaluate_admission(&db, "agent:fixture", "acme", "other", "", 41).unwrap(),
            AdmissionAutonomy::ProposeOnly
        ));
        stop_envelope(&db, "agent:fixture", "acme", "auto:dispatch", 50).unwrap();
        assert!(matches!(
            evaluate_admission(&db, "agent:fixture", "acme", "dispatch", "", 60).unwrap(),
            AdmissionAutonomy::ProposeOnly
        ));
        let revoked = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        assert_eq!(revoked.status, STATUS_REVOKED);
        assert_eq!(revoked.revoke_reason, REASON_ENVELOPE);
        let receipts = db
            .list_decisions(&DecisionFilter {
                action: Some(ACTION_REVOKE.into()),
                ..DecisionFilter::default()
            })
            .unwrap();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn a_different_submitted_envelope_does_not_auto_apply() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        envelope(&db, "auto:other", 9);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        assert!(matches!(
            evaluate_admission(&db, "agent:fixture", "acme", "dispatch", "auto:other", 40).unwrap(),
            AdmissionAutonomy::ProposeOnly
        ));
        let live = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        assert_eq!(live.status, STATUS_LIVE_GRANT);
        assert!(matches!(
            evaluate_admission(
                &db,
                "agent:fixture",
                "acme",
                "dispatch",
                "auto:dispatch",
                41
            )
            .unwrap(),
            AdmissionAutonomy::AutoApply { envelope_id } if envelope_id == "auto:dispatch"
        ));
    }

    #[test]
    fn a_later_denial_revokes_on_the_next_admit_check() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        parked(&db, "agent:fixture", "dispatch", "c", DECISION_DENY, 80);
        assert!(matches!(
            evaluate_admission(&db, "agent:fixture", "acme", "dispatch", "", 90).unwrap(),
            AdmissionAutonomy::ProposeOnly
        ));
        let revoked = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        assert_eq!(revoked.revoke_reason, REASON_REJECTED);
    }

    #[test]
    fn rejected_action_revokes_a_live_grant() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        revoke_if_granted(&db, "ops-admin", "acme", "agent:fixture", "dispatch", 70).unwrap();
        let revoked = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        assert_eq!(revoked.revoke_reason, REASON_REJECTED);
        assert!(matches!(
            evaluate_admission(&db, "agent:fixture", "acme", "dispatch", "", 80).unwrap(),
            AdmissionAutonomy::ProposeOnly
        ));
    }

    #[test]
    fn model_pin_change_revokes_auto_apply() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        let live = envelope(&db, "auto:dispatch", 3);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        let mut stale = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        stale.model_digest = live.pins.policy_digest.clone();
        db.put_agent_autonomy(&stale).unwrap();
        assert!(matches!(
            evaluate_admission(&db, "agent:fixture", "acme", "dispatch", "", 90).unwrap(),
            AdmissionAutonomy::ProposeOnly
        ));
        let revoked = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        assert_eq!(revoked.revoke_reason, REASON_MODEL_CHANGE);
    }

    #[test]
    fn admit_parks_agents_until_grant_then_auto_applies_only_that_type() {
        use crate::sekai::action_instance_admission::{
            ActionInstanceAdmission, ActionInstanceAdmissionRequest,
        };
        use crate::sekai::object_security::PrincipalPolicyContext;

        let db = setup();
        db.put_governed_action_type(
            GovernedActionType {
                namespace: "acme".into(),
                type_id: "notify".into(),
                version: "1".into(),
                description: "notify".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                object_kind: String::new(),
                object_mutation: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("acme");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::Allow;
        db.upsert_action_policy(&policy).unwrap();
        let admission = ActionInstanceAdmission::new(&db, None);
        let req = |type_id: &str, key: &str| ActionInstanceAdmissionRequest {
            agent_turn: None,
            namespace: "acme".into(),
            type_id: type_id.into(),
            version: "1".into(),
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            idempotency_key: key.into(),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: String::new(),
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
        };
        let human = admission
            .admit(req("dispatch", "human-1"), "alice", 5)
            .unwrap()
            .instance;
        assert_eq!(human.status, STATUS_ADMITTED);
        let parked_agent = admission
            .admit(req("dispatch", "agent-1"), "agent:fixture", 6)
            .unwrap()
            .instance;
        assert_eq!(
            parked_agent.status,
            crate::sekai::action_instance::STATUS_PARKED
        );
        parked(
            &db,
            "agent:fixture",
            "dispatch",
            "hist-a",
            DECISION_GRANT,
            10,
        );
        parked(
            &db,
            "agent:fixture",
            "dispatch",
            "hist-b",
            DECISION_GRANT,
            20,
        );
        envelope(&db, "auto:dispatch", 3);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        let auto = admission
            .admit(req("dispatch", "agent-2"), "agent:fixture", 40)
            .unwrap()
            .instance;
        assert_eq!(auto.status, STATUS_ADMITTED);
        assert_eq!(auto.policy_decision, "auto_apply");
        assert_eq!(auto.autonomous_envelope_id, "auto:dispatch");
        let other = admission
            .admit(req("notify", "agent-3"), "agent:fixture", 41)
            .unwrap()
            .instance;
        assert_eq!(other.status, crate::sekai::action_instance::STATUS_PARKED);
        envelope(&db, "auto:other", 9);
        let mut swapped = req("dispatch", "agent-4");
        swapped.autonomous_envelope_id = "auto:other".into();
        let parked_swap = admission
            .admit(swapped, "agent:fixture", 42)
            .unwrap()
            .instance;
        assert_eq!(
            parked_swap.status,
            crate::sekai::action_instance::STATUS_PARKED
        );
        assert_ne!(parked_swap.policy_decision, "auto_apply");
        assert_eq!(parked_swap.autonomous_envelope_id, "auto:other");
        db.put_governed_action_type(
            GovernedActionType {
                namespace: "acme".into(),
                type_id: "autonomous.dispatch".into(),
                version: "1".into(),
                description: "autonomous dispatch".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                policy_scope: String::new(),
                budget_scope: String::new(),
                object_kind: String::new(),
                object_mutation: String::new(),
                enabled: true,
                created_by: String::new(),
                created_at_ms: 0,
                updated_at_ms: 0,
                disabled_at_ms: 0,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        parked(
            &db,
            "agent:fixture",
            "autonomous.dispatch",
            "auto-hist-a",
            DECISION_GRANT,
            50,
        );
        parked(
            &db,
            "agent:fixture",
            "autonomous.dispatch",
            "auto-hist-b",
            DECISION_GRANT,
            51,
        );
        envelope(&db, "auto:autonomous", 3);
        grant_auto_apply(
            &db,
            grant_req(
                "agent:fixture",
                "autonomous.dispatch",
                "auto:autonomous",
                52,
            ),
        )
        .unwrap();
        let autonomous = admission
            .admit(req("autonomous.dispatch", "agent-5"), "agent:fixture", 53)
            .unwrap()
            .instance;
        assert_eq!(autonomous.status, STATUS_ADMITTED);
        assert_eq!(autonomous.policy_decision, "auto_apply");
        assert_eq!(autonomous.autonomous_envelope_id, "auto:autonomous");
    }

    #[test]
    fn a_second_live_grant_does_not_replace_the_first() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        let first = grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        let mut other = first.clone();
        other.envelope_id = "auto:other".into();
        other.granted_at_ms = 99;
        db.put_agent_autonomy(&other).unwrap_err();
        let kept = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        assert_eq!(kept.envelope_id, "auto:dispatch");
        assert_eq!(kept.granted_at_ms, 30);
    }

    #[test]
    fn a_stale_revoke_does_not_clobber_a_later_grant() {
        let db = setup();
        parked(&db, "agent:fixture", "dispatch", "a", DECISION_GRANT, 10);
        parked(&db, "agent:fixture", "dispatch", "b", DECISION_GRANT, 20);
        envelope(&db, "auto:dispatch", 3);
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 30),
        )
        .unwrap();
        let first = revoke_auto_apply(
            &db,
            "ops-admin",
            "acme",
            "agent:fixture",
            "dispatch",
            REASON_ADMIN,
            40,
        )
        .unwrap()
        .unwrap();
        grant_auto_apply(
            &db,
            grant_req("agent:fixture", "dispatch", "auto:dispatch", 50),
        )
        .unwrap();
        db.put_agent_autonomy(&first).unwrap_err();
        let kept = db
            .get_agent_autonomy("acme", "agent:fixture", "dispatch")
            .unwrap()
            .unwrap();
        assert_eq!(kept.status, STATUS_LIVE_GRANT);
        assert_eq!(kept.granted_at_ms, 50);
    }
}
