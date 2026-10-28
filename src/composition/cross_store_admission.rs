//! Reserve → submit → finalize across typed Chisei and Sekai stores.
//!
//! No shared transaction. Timeout is not rejection. Reconcile finalizes only
//! after Sekai reports committed, and releases only after a successful absent
//! lookup past expiry.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::chisei::budget::BudgetTracker;
use crate::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
};
use crate::chisei::sekai_commit::{SekaiCommitLookup, SekaiCommitRef};
use crate::chisei::system_one_action::SystemOneProposal;
use crate::chisei_store::{ChiseiReceiptStore, ChiseiStore};
use crate::db::chisei_operation_reservation::{
    OperationReservation, RESERVATION_FINALIZED, RESERVATION_PENDING, RESERVATION_RELEASED,
};
use crate::db::store::SekaiStore;
use crate::sekai::action_instance::{
    compute_request_digest_with_envelope, submit_budget_subject, validate_parameters_json,
};
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionOutcome,
    ActionInstanceAdmissionRequest,
};
use crate::sekai::action_ports::{ActionBudgetPort, ActionProposalPort};

pub const DEFAULT_RESERVATION_TTL_MS: i64 = 15 * 60 * 1_000;

#[derive(Clone)]
pub struct CrossStoreAdmission {
    chisei: ChiseiStore,
    sekai: SekaiStore,
    budget: Option<Arc<BudgetTracker>>,
    distinct_stores: bool,
    reservation_ttl_ms: i64,
}

impl CrossStoreAdmission {
    pub(crate) fn new(
        chisei: ChiseiStore,
        sekai: SekaiStore,
        budget: Option<Arc<BudgetTracker>>,
    ) -> Self {
        let distinct_stores = !chisei.shares_physical_store_with(&sekai);
        Self {
            chisei,
            sekai,
            budget,
            distinct_stores,
            reservation_ttl_ms: DEFAULT_RESERVATION_TTL_MS,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_reservation_ttl_ms(mut self, ttl_ms: i64) -> Self {
        self.reservation_ttl_ms = ttl_ms.max(1);
        self
    }

    #[cfg(test)]
    pub(crate) fn distinct_stores(&self) -> bool {
        self.distinct_stores
    }

    pub(crate) fn chisei_runtime_arc(&self) -> Arc<crate::db::runtime_db::RuntimeDb> {
        self.chisei.runtime_arc()
    }

    pub(crate) fn budget_port(&self) -> Option<&dyn ActionBudgetPort> {
        self.budget
            .as_ref()
            .map(|budget| budget.as_ref() as &dyn ActionBudgetPort)
    }

    pub(crate) fn proposal_port(&self) -> &dyn ActionProposalPort {
        &SystemOneProposal
    }

    pub(crate) fn reserve(
        &self,
        request: &ActionInstanceAdmissionRequest,
        actor: &str,
        now_ms: i64,
    ) -> Result<OperationReservation, ActionInstanceAdmissionError> {
        let namespace = request.namespace.trim();
        require_value("namespace", namespace)?;
        require_value("type_id", request.type_id.trim())?;
        validate_parameters_json(&request.parameters_json)
            .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
        let operation_id = resolve_operation_id(&request.request_id)?;
        let envelope_id = request.autonomous_envelope_id.trim();
        let mut evidence_ids = request.evidence_submission_ids.clone();
        evidence_ids.sort();
        evidence_ids.dedup();
        let request_digest = compute_request_digest_with_envelope(
            namespace,
            &request.type_id,
            &request.version,
            &request.parameters_json,
            &evidence_ids,
            envelope_id,
        )
        .map_err(ActionInstanceAdmissionError::InvalidArgument)?;

        let existing = self
            .chisei
            .get_operation_reservation(namespace, &operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        if let Some(existing) = existing.as_ref() {
            if existing.request_digest != request_digest {
                return Err(ActionInstanceAdmissionError::AlreadyExists(
                    "operation identity conflict: same (namespace, operation_id) with different request digest".into(),
                ));
            }
            if existing.status != RESERVATION_RELEASED {
                return Ok(existing.clone());
            }
        }

        // Charge the action type's budget scope, as combined admission does;
        // the type lives in the Sekai store (#1863).
        let type_def = self
            .sekai
            .runtime()
            .require_enabled_governed_action_type(namespace, &request.type_id, &request.version)
            .map_err(|error| {
                if error.contains("unknown") || error.contains("disabled") {
                    ActionInstanceAdmissionError::FailedPrecondition(error)
                } else {
                    ActionInstanceAdmissionError::Internal(error)
                }
            })?;
        let budget_subject = submit_budget_subject(namespace, actor, &type_def.budget_scope);
        if let Some(budget) = &self.budget {
            let budget_key = if let Some(row) = existing
                .as_ref()
                .filter(|row| row.status == RESERVATION_RELEASED)
            {
                format!("{operation_id}:reacquire:{}", row.updated_at_ms)
            } else {
                operation_id.clone()
            };
            budget
                .check_and_reserve_idempotent(&budget_subject, 1, &budget_key)
                .map_err(|error| {
                    if error.contains("exceeded") || error.contains("budget") {
                        ActionInstanceAdmissionError::FailedPrecondition(error)
                    } else {
                        ActionInstanceAdmissionError::Internal(error)
                    }
                })?;
        }

        let reservation = OperationReservation {
            namespace: namespace.to_string(),
            operation_id: operation_id.clone(),
            request_digest,
            status: RESERVATION_PENDING.into(),
            actor: actor.to_string(),
            budget_subject: budget_subject.clone(),
            incurred_usage: 1,
            sekai_instance_id: String::new(),
            sekai_status: String::new(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(self.reservation_ttl_ms),
        };
        let stored = self
            .chisei
            .put_operation_reservation(&reservation)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        if self.distinct_stores {
            self.write_decision_receipt(&stored, None, now_ms)?;
        }
        Ok(stored)
    }

    pub(crate) fn submit_sekai(
        &self,
        mut request: ActionInstanceAdmissionRequest,
        actor: &str,
        now_ms: i64,
        tenant: &str,
        machine_credential: bool,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        request.budget_already_reserved = self.budget.is_some();
        ActionInstanceAdmission::new(self.sekai.runtime(), self.budget_port())
            .with_proposal(Some(self.proposal_port()))
            .with_tenant(tenant)
            .with_machine_credential(machine_credential)
            .admit(request, actor, now_ms)
    }

    pub(crate) fn finalize(
        &self,
        reservation: &OperationReservation,
        commit: Option<&SekaiCommitRef>,
        now_ms: i64,
    ) -> Result<OperationReservation, ActionInstanceAdmissionError> {
        if !reservation.is_pending() {
            return Ok(reservation.clone());
        }
        let mut next = reservation.clone();
        next.status = RESERVATION_FINALIZED.into();
        next.updated_at_ms = now_ms;
        if let Some(commit) = commit {
            next.sekai_instance_id = commit.instance_id.clone();
            next.sekai_status = commit.status.clone();
        }
        let stored = self
            .chisei
            .put_operation_reservation(&next)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        if self.distinct_stores {
            self.write_decision_receipt(
                &stored,
                commit.map(|commit| commit.marking.as_str()),
                now_ms,
            )?;
        }
        Ok(stored)
    }

    pub(crate) fn release(
        &self,
        reservation: &OperationReservation,
        now_ms: i64,
    ) -> Result<OperationReservation, ActionInstanceAdmissionError> {
        if !reservation.is_pending() {
            return Ok(reservation.clone());
        }
        if reservation.incurred_usage > 0
            && let Some(budget) = &self.budget
        {
            budget.adjust(
                &reservation.budget_subject,
                reservation.incurred_usage as i32,
                0,
            );
        }
        let mut next = reservation.clone();
        next.status = RESERVATION_RELEASED.into();
        next.updated_at_ms = now_ms;
        next.incurred_usage = 0;
        self.chisei
            .put_operation_reservation(&next)
            .map_err(ActionInstanceAdmissionError::Internal)
    }

    pub(crate) fn reconcile_one(
        &self,
        reservation: &OperationReservation,
        now_ms: i64,
    ) -> Result<OperationReservation, ActionInstanceAdmissionError> {
        if !reservation.is_pending() {
            return Ok(reservation.clone());
        }
        match self
            .sekai
            .lookup_commit(&reservation.operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)
        {
            Ok(Some(commit)) => self.finalize(reservation, Some(&commit), now_ms),
            Ok(None) if now_ms >= reservation.expires_at_ms => self.release(reservation, now_ms),
            Ok(None) => Ok(reservation.clone()),
            Err(_) => Ok(reservation.clone()),
        }
    }

    pub(crate) fn reconcile_pending(
        &self,
        now_ms: i64,
    ) -> Result<Vec<OperationReservation>, ActionInstanceAdmissionError> {
        let pending = self
            .chisei
            .list_pending_operation_reservations(256)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        pending
            .iter()
            .map(|reservation| self.reconcile_one(reservation, now_ms))
            .collect()
    }

    pub(crate) fn admit(
        &self,
        request: ActionInstanceAdmissionRequest,
        actor: &str,
        now_ms: i64,
        tenant: &str,
        machine_credential: bool,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let namespace = request.namespace.trim();
        let operation_id = resolve_operation_id(&request.request_id)?;
        let existing = self
            .chisei
            .get_operation_reservation(namespace, &operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        if existing
            .as_ref()
            .is_none_or(|row| row.status == RESERVATION_RELEASED)
        {
            refuse_admission_freeze(
                self.sekai.runtime(),
                &request,
                actor,
                tenant,
                machine_credential,
            )?;
            // A fresh request Sekai would refuse before writing, invalid
            // parameters among them, is refused before any budget is
            // reserved (#1864). A replay of an existing reservation skips
            // this, so it still returns its committed outcome.
            ActionInstanceAdmission::new(self.sekai.runtime(), self.budget_port())
                .check_request(&request)?;
        }
        let reserved = self.reserve(&request, actor, now_ms)?;
        let outcome = match self.submit_sekai(request, actor, now_ms, tenant, machine_credential) {
            Ok(outcome) => outcome,
            Err(error) => {
                // A refusal that admitted nothing gives the charge back: a
                // freeze, or a submitter not cleared for the marking (#1706).
                if is_write_freeze_refusal(&error)
                    || matches!(error, ActionInstanceAdmissionError::PermissionDenied(_))
                {
                    let _ = self.release(&reserved, now_ms);
                } else {
                    let _ = self.finalize(&reserved, None, now_ms);
                }
                return Err(error);
            }
        };
        let commit = SekaiCommitRef {
            namespace: outcome.instance.namespace.clone(),
            instance_id: outcome.instance.instance_id.clone(),
            status: outcome.instance.status.clone(),
            marking: outcome.instance.marking.clone(),
        };
        self.finalize(&reserved, Some(&commit), now_ms)?;
        Ok(outcome)
    }

    /// `marking` is the committed instance's (#1706); the receipt then needs
    /// clearance for it, as the instance does.
    fn write_decision_receipt(
        &self,
        reservation: &OperationReservation,
        marking: Option<&str>,
        now_ms: i64,
    ) -> Result<(), ActionInstanceAdmissionError> {
        let mut attributes = BTreeMap::from([
            ("reservation_status".into(), reservation.status.clone()),
            ("request_digest".into(), reservation.request_digest.clone()),
            ("budget_subject".into(), reservation.budget_subject.clone()),
        ]);
        if !reservation.sekai_instance_id.is_empty() {
            attributes.insert(
                "sekai_commit_instance_id".into(),
                reservation.sekai_instance_id.clone(),
            );
            attributes.insert(
                "sekai_commit_status".into(),
                reservation.sekai_status.clone(),
            );
        }
        if let Some(marking) = marking.filter(|marking| !marking.is_empty()) {
            attributes.insert(
                crate::chisei::sekai_commit::RECEIPT_MARKING_ATTRIBUTE.into(),
                marking.to_string(),
            );
        }
        let completed_at_ms = (reservation.status != RESERVATION_PENDING).then_some(now_ms);
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: reservation.operation_id.clone(),
            parent_operation_id: None,
            namespace: reservation.namespace.clone(),
            operation_class: "chisei_admission_reservation".into(),
            initiating_actor: reservation.actor.clone(),
            schema_version: "admission-reservation/v1".into(),
            policy_version: "typed-hop".into(),
            started_at_ms: reservation.created_at_ms,
            completed_at_ms,
            events: vec![OperationReceiptEvent {
                event_id: format!("{}:reservation", reservation.operation_id),
                operation_id: reservation.operation_id.clone(),
                parent_event_id: None,
                timestamp_ms: now_ms,
                surface: ReceiptEventKind::BudgetDecided.surface(),
                kind: ReceiptEventKind::BudgetDecided,
                actor: reservation.actor.clone(),
                references: Vec::new(),
                attributes,
            }],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        };
        self.chisei
            .put_operation_receipt(&receipt)
            .map_err(ActionInstanceAdmissionError::Internal)
    }
}

fn refuse_admission_freeze(
    db: &crate::db::runtime_db::RuntimeDb,
    request: &ActionInstanceAdmissionRequest,
    actor: &str,
    tenant: &str,
    machine_credential: bool,
) -> Result<(), ActionInstanceAdmissionError> {
    let agent = crate::sekai::write_freeze::actor_is_agent(
        db,
        actor,
        request.delegating_actor.as_deref(),
        machine_credential,
    )
    .map_err(ActionInstanceAdmissionError::Internal)?;
    let tenant = crate::sekai::write_freeze::acting_or_registered_tenant(db, tenant, actor)
        .map_err(ActionInstanceAdmissionError::Internal)?;
    let namespace = request.namespace.trim();
    let mut checks = crate::sekai::write_freeze::write_checks_for_actors(
        namespace,
        tenant.as_ref(),
        actor,
        request.delegating_actor.as_deref(),
        request.type_id.trim(),
        agent,
    );
    if !request.resource_tenant.is_empty() && request.resource_tenant != tenant.as_ref() {
        checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
            namespace,
            &request.resource_tenant,
            actor,
            request.delegating_actor.as_deref(),
            request.type_id.trim(),
            agent,
        ));
    }
    match crate::sekai::write_freeze::freeze_reason_any(db, &checks) {
        Ok(Some(reason)) => Err(ActionInstanceAdmissionError::FailedPrecondition(reason)),
        Ok(None) => Ok(()),
        Err(error) => Err(ActionInstanceAdmissionError::Internal(error)),
    }
}

fn is_write_freeze_refusal(error: &ActionInstanceAdmissionError) -> bool {
    matches!(
        error,
        ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze")
    )
}

fn require_value(name: &str, value: &str) -> Result<(), ActionInstanceAdmissionError> {
    if value.is_empty() {
        Err(ActionInstanceAdmissionError::InvalidArgument(format!(
            "{name} required"
        )))
    } else {
        Ok(())
    }
}

fn resolve_operation_id(request_id: &str) -> Result<String, ActionInstanceAdmissionError> {
    let request_id = request_id.trim();
    if request_id.is_empty() {
        return Err(ActionInstanceAdmissionError::InvalidArgument(
            "request_id required".into(),
        ));
    }
    if request_id.chars().any(char::is_whitespace) {
        return Err(ActionInstanceAdmissionError::InvalidArgument(
            "request_id must not contain whitespace".into(),
        ));
    }
    Ok(request_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::budget::PeriodType;
    use crate::sekai::governed_action_type::{EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType};
    use tempfile::tempdir;

    fn dest_pair() -> (SekaiStore, ChiseiStore) {
        let dir = tempdir().unwrap();
        let sekai = dir.path().join("sekai.db");
        let chisei = dir.path().join("chisei.db");
        let sekai = SekaiStore::open_sqlite(sekai.to_str().unwrap());
        let chisei = ChiseiStore::open_sqlite(chisei.to_str().unwrap());
        std::mem::forget(dir);
        (sekai, chisei)
    }

    fn seed_type(sekai: &SekaiStore) {
        sekai
            .runtime().put_governed_action_type(
                GovernedActionType {
                    namespace: "acme".into(),
                    type_id: "dispatch".into(),
                    version: "1".into(),
                    description: "dispatch work".into(),
                    parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                    allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                    enabled: true,
                    ..Default::default()
                },
                "operator",
                1,
            )
            .unwrap();
    }

    fn request(operation_id: &str) -> ActionInstanceAdmissionRequest {
        ActionInstanceAdmissionRequest {
            namespace: "acme".into(),
            type_id: "dispatch".into(),
            version: "1".into(),
            parameters_json: r#"{"runtime":"shikigami"}"#.into(),
            idempotency_key: operation_id.into(),
            evidence_submission_ids: Vec::new(),
            request_id: operation_id.into(),
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
        }
    }

    fn clerk_with_budget() -> (CrossStoreAdmission, Arc<BudgetTracker>) {
        let (sekai, chisei) = dest_pair();
        seed_type(&sekai);
        let budget = Arc::new(BudgetTracker::new(chisei.clone()));
        budget
            .set_limit("action:governed", 8, PeriodType::Daily)
            .unwrap();
        (
            CrossStoreAdmission::new(chisei, sekai, Some(budget.clone())),
            budget,
        )
    }

    /// On split stores a type's `budget_scope` is charged, as on the combined
    /// layout: it exhausts its own scope and leaves the namespace budget
    /// alone (#1863).
    #[test]
    fn split_admission_charges_the_action_type_budget_scope() {
        let (sekai, chisei) = dest_pair();
        seed_type(&sekai);
        sekai
            .runtime()
            .put_governed_action_type(
                GovernedActionType {
                    namespace: "acme".into(),
                    type_id: "payout".into(),
                    version: "1".into(),
                    description: "pay from the treasury".into(),
                    parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
                    allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                    enabled: true,
                    budget_scope: "treasury".into(),
                    ..Default::default()
                },
                "operator",
                1,
            )
            .unwrap();
        let budget = Arc::new(BudgetTracker::new(chisei.clone()));
        budget
            .set_limit("action:governed", 1, PeriodType::Daily)
            .unwrap();
        budget
            .set_limit("action:governed:treasury", 1, PeriodType::Daily)
            .unwrap();
        let clerk = CrossStoreAdmission::new(chisei, sekai, Some(budget));
        assert!(clerk.distinct_stores());
        let payout = |operation_id: &str| ActionInstanceAdmissionRequest {
            type_id: "payout".into(),
            ..request(operation_id)
        };

        let first = clerk.reserve(&payout("op-pay-1"), "alice", 10).unwrap();
        assert_eq!(
            first.budget_subject,
            "action:governed:treasury/project:acme/agent:alice"
        );
        assert!(matches!(
            clerk.reserve(&payout("op-pay-2"), "alice", 11),
            Err(ActionInstanceAdmissionError::FailedPrecondition(_))
        ));
        // The namespace budget is still unspent.
        let unscoped = clerk.reserve(&request("op-dispatch"), "alice", 12).unwrap();
        assert_eq!(
            unscoped.budget_subject,
            "action:governed/project:acme/agent:alice"
        );
    }

    #[test]
    fn crash_after_reserve_keeps_pending() {
        let (clerk, _) = clerk_with_budget();
        let reserved = clerk.reserve(&request("op-reserve"), "alice", 10).unwrap();
        assert_eq!(reserved.status, RESERVATION_PENDING);
        assert!(
            clerk
                .sekai
                .runtime()
                .get_action_instance_by_operation_id("op-reserve")
                .unwrap()
                .is_none()
        );
        let again = clerk.reconcile_one(&reserved, 11).unwrap();
        assert_eq!(again.status, RESERVATION_PENDING);
    }

    #[test]
    fn crash_after_commit_reconcile_finalizes() {
        let (clerk, _) = clerk_with_budget();
        let req = request("op-commit");
        let _reserved = clerk.reserve(&req, "alice", 10).unwrap();
        let outcome = clerk.submit_sekai(req, "alice", 11, "", false).unwrap();
        assert_eq!(outcome.instance.status, "admitted");
        let still = clerk
            .chisei
            .get_operation_reservation("acme", "op-commit")
            .unwrap()
            .unwrap();
        assert_eq!(still.status, RESERVATION_PENDING);
        let finalized = clerk.reconcile_one(&still, 12).unwrap();
        assert_eq!(finalized.status, RESERVATION_FINALIZED);
        assert_eq!(finalized.sekai_instance_id, outcome.instance.instance_id);
        assert_ne!(finalized.sekai_status, "rejected");
    }

    #[test]
    fn duplicate_identity_is_idempotent_and_digest_mismatch_fails_closed() {
        let (clerk, _) = clerk_with_budget();
        let first = clerk.reserve(&request("op-dup"), "alice", 10).unwrap();
        let replay = clerk.reserve(&request("op-dup"), "alice", 11).unwrap();
        assert_eq!(first.request_digest, replay.request_digest);
        assert_eq!(replay.status, RESERVATION_PENDING);
        let mut conflict = request("op-dup");
        conflict.parameters_json = r#"{"runtime":"other"}"#.into();
        let error = clerk.reserve(&conflict, "alice", 12).unwrap_err();
        assert!(matches!(
            error,
            ActionInstanceAdmissionError::AlreadyExists(_)
        ));
    }

    /// #1864: on distinct stores, a submit refused for invalid parameters
    /// reserves nothing; only the admitted one consumes a unit.
    #[test]
    fn invalid_parameters_are_refused_before_any_budget_is_reserved() {
        let (clerk, budget) = clerk_with_budget();
        let used_before = budget.get_usage("action:governed").tokens_used;
        let mut invalid = request("op-invalid");
        invalid.parameters_json = r#"{"runtime":7}"#.into();
        let error = clerk.admit(invalid, "alice", 10, "", false).unwrap_err();
        assert!(
            matches!(error, ActionInstanceAdmissionError::InvalidArgument(_)),
            "{error:?}"
        );
        assert_eq!(budget.get_usage("action:governed").tokens_used, used_before);
        assert!(
            clerk
                .chisei
                .get_operation_reservation("acme", "op-invalid")
                .unwrap()
                .is_none()
        );
        clerk
            .admit(request("op-valid"), "alice", 11, "", false)
            .unwrap();
        assert_eq!(
            budget.get_usage("action:governed").tokens_used,
            used_before + 1
        );
    }

    #[test]
    fn freeze_refusal_releases_budget() {
        let (clerk, budget) = clerk_with_budget();
        clerk
            .sekai
            .runtime()
            .set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
                scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
                scope_value: "acme".into(),
                mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
                reason: "incident".into(),
                enabled: true,
                updated_ms: 1,
            })
            .unwrap();
        let used_before = budget.get_usage("action:governed").tokens_used;
        let error = clerk
            .admit(request("op-frozen"), "alice", 10, "", false)
            .unwrap_err();
        assert!(
            matches!(error, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains("write freeze"))
        );
        assert_eq!(budget.get_usage("action:governed").tokens_used, used_before);
        assert!(
            clerk
                .chisei
                .get_operation_reservation("acme", "op-frozen")
                .unwrap()
                .is_none()
        );
        assert!(
            clerk
                .sekai
                .runtime()
                .get_action_instance_by_operation_id("op-frozen")
                .unwrap()
                .is_none()
        );
        clerk
            .sekai
            .runtime()
            .set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
                scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
                scope_value: "acme".into(),
                mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
                reason: "lifted".into(),
                enabled: false,
                updated_ms: 2,
            })
            .unwrap();
        clerk
            .admit(request("op-frozen"), "alice", 20, "", false)
            .unwrap();
        assert!(budget.get_usage("action:governed").tokens_used > used_before);
        assert_eq!(
            clerk
                .chisei
                .get_operation_reservation("acme", "op-frozen")
                .unwrap()
                .unwrap()
                .status,
            RESERVATION_FINALIZED
        );
    }

    #[test]
    fn rejected_mutation_keeps_reserved_usage() {
        let (clerk, budget) = clerk_with_budget();
        let reserved = clerk.reserve(&request("op-deny"), "alice", 10).unwrap();
        let used_after_reserve = budget.get_usage("action:governed").tokens_used;
        assert!(used_after_reserve >= 1);
        clerk.finalize(&reserved, None, 11).unwrap();
        assert_eq!(
            budget.get_usage("action:governed").tokens_used,
            used_after_reserve
        );
    }

    #[test]
    fn timeout_without_sekai_lookup_stays_pending() {
        let (sekai, chisei) = dest_pair();
        seed_type(&sekai);
        let clerk = CrossStoreAdmission::new(chisei, sekai, None).with_reservation_ttl_ms(5);
        let reserved = clerk.reserve(&request("op-timeout"), "alice", 10).unwrap();
        let after = clerk.reconcile_one(&reserved, 12).unwrap();
        assert_eq!(after.status, RESERVATION_PENDING);
        let released = clerk.reconcile_one(&reserved, 20).unwrap();
        assert_eq!(released.status, RESERVATION_RELEASED);
    }

    #[test]
    fn admit_writes_plane_specific_receipts_without_copying_bodies() {
        let (clerk, _) = clerk_with_budget();
        assert!(clerk.distinct_stores());
        let outcome = clerk
            .admit(request("op-receipts"), "alice", 10, "", false)
            .unwrap();
        let chisei_receipt = clerk
            .chisei
            .get_operation_receipt("op-receipts")
            .unwrap()
            .expect("chisei decision receipt");
        assert_eq!(
            chisei_receipt.operation_class,
            "chisei_admission_reservation"
        );
        let sekai_receipt = clerk
            .sekai
            .runtime()
            .get_operation_receipt("op-receipts")
            .unwrap()
            .expect("sekai commit receipt");
        assert_eq!(sekai_receipt.operation_class, "governed_action_instance");
        assert_ne!(chisei_receipt.events, sekai_receipt.events);
        assert_eq!(
            clerk
                .chisei
                .get_operation_reservation("acme", "op-receipts")
                .unwrap()
                .unwrap()
                .sekai_instance_id,
            outcome.instance.instance_id
        );
    }

    #[test]
    fn shared_runtime_admit_reuses_one_receipt_authority() {
        let sekai = SekaiStore::memory();
        let chisei = ChiseiStore::from_shared_runtime(sekai.runtime_arc());
        seed_type(&sekai);
        let clerk = CrossStoreAdmission::new(chisei, sekai, None);
        assert!(!clerk.distinct_stores());
        clerk
            .admit(request("op-shared"), "alice", 10, "", false)
            .unwrap();
        let receipt = clerk
            .chisei
            .get_operation_receipt("op-shared")
            .unwrap()
            .expect("shared receipt");
        assert_eq!(receipt.operation_class, "governed_action_instance");
    }
}
