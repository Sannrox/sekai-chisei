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
use crate::chisei_store::{
    ChiseiReceiptStore, ChiseiStore, OperationReservation, RESERVATION_FINALIZED,
    RESERVATION_PENDING, RESERVATION_RELEASED,
};
use crate::db::store::SekaiStore;
use crate::sekai::action_instance::{
    compute_request_digest_with_envelope, validate_parameters_json,
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

    /// The reservation step alone, as [`Self::admit`] runs it; tests drive it
    /// directly to stop admission between its steps.
    #[cfg(test)]
    pub(crate) fn reserve(
        &self,
        request: &ActionInstanceAdmissionRequest,
        actor: &str,
        now_ms: i64,
    ) -> Result<OperationReservation, ActionInstanceAdmissionError> {
        self.try_reserve(request, actor, now_ms)?
            .map_err(ActionInstanceAdmissionError::FailedPrecondition)
    }

    /// [`Self::reserve`], with a budget refusal kept apart from other errors so
    /// [`Self::admit`] can record it: the inner error is the exhaustion
    /// message. A refusal stores and charges nothing.
    fn try_reserve(
        &self,
        request: &ActionInstanceAdmissionRequest,
        actor: &str,
        now_ms: i64,
    ) -> Result<Result<OperationReservation, String>, ActionInstanceAdmissionError> {
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
                return Ok(Ok(existing.clone()));
            }
        }
        // Sekai may already hold this operation as a denial recorded by a
        // budget refusal (by the budget, or by policy first), which has no
        // reservation; any other denial has a finalized one and returned
        // above. Charge nothing and persist nothing: Sekai admission replays
        // a matching retry, after which `repair_replayed` writes its receipt,
        // and refuses a changed one. Admitted work is reserved as before
        // (#1871).
        if let Some(denied) = self
            .sekai
            .runtime()
            .get_action_instance_by_operation_id(&operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .filter(|instance| instance.status == crate::sekai::action_instance::STATUS_DENIED)
        {
            return Ok(Ok(OperationReservation {
                namespace: namespace.to_string(),
                operation_id: operation_id.clone(),
                request_digest: request_digest.clone(),
                status: RESERVATION_FINALIZED.into(),
                actor: actor.to_string(),
                budget_subject: String::new(),
                incurred_usage: 0,
                sekai_instance_id: denied.instance_id,
                sekai_status: denied.status,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
                expires_at_ms: now_ms,
                charge_key: String::new(),
            }));
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
        let (budget_subject, budget_amount) = type_def
            .budget_charge(namespace, actor, &request.parameters_json)
            .map_err(ActionInstanceAdmissionError::InvalidArgument)?;
        // The charge's key, recorded on the reservation so settlement finds
        // the charge and refunds into its period (#1902). A reacquisition is
        // keyed by the release it follows, which stays the same across
        // retries until the row is rewritten.
        let mut charge_key = String::new();
        if let Some(budget) = &self.budget {
            charge_key = match existing
                .as_ref()
                .filter(|row| row.status == RESERVATION_RELEASED)
            {
                Some(row) => format!("{operation_id}:reacquire:{}", row.updated_at_ms),
                None => operation_id.clone(),
            };
            let budget_key = &charge_key;
            if let Err(error) = budget.check_and_reserve_idempotent_at(
                &budget_subject,
                budget_amount,
                budget_key,
                now_ms,
            ) {
                // Only exhaustion is a refusal worth recording. Routing
                // (home-site pins) and store failures stay retryable.
                if !error.contains(BUDGET_EXHAUSTED) {
                    return Err(if error.contains("exceeded") || error.contains("budget") {
                        ActionInstanceAdmissionError::FailedPrecondition(error)
                    } else {
                        ActionInstanceAdmissionError::Internal(error)
                    });
                }
                return Ok(Err(error));
            }
        }

        let reservation = OperationReservation {
            namespace: namespace.to_string(),
            operation_id: operation_id.clone(),
            request_digest,
            status: RESERVATION_PENDING.into(),
            actor: actor.to_string(),
            budget_subject: budget_subject.clone(),
            incurred_usage: i64::from(budget_amount),
            sekai_instance_id: String::new(),
            sekai_status: String::new(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(self.reservation_ttl_ms),
            charge_key,
        };
        let stored = self
            .chisei
            .put_operation_reservation(&reservation)
            .map_err(ActionInstanceAdmissionError::Internal)?;
        if self.distinct_stores {
            self.write_decision_receipt(&stored, None, now_ms)?;
        }
        Ok(Ok(stored))
    }

    /// Record a budget refusal as combined admission does: Sekai admission
    /// stores the denied instance, its receipt and an
    /// `action_instance_budget_denied` decision, never parks it, and charges
    /// nothing. No Chisei reservation is written, so a concurrent attempt's
    /// reservation is never overwritten; a retry adopts the recorded outcome
    /// in [`Self::try_reserve`] and [`Self::repair_replayed`] writes its
    /// receipt (#1871). The caller gets the budget refusal, as before,
    /// unless another attempt committed the operation first.
    fn record_budget_refusal(
        &self,
        mut request: ActionInstanceAdmissionRequest,
        refusal: String,
        actor: &str,
        now_ms: i64,
        tenant: &str,
        machine_credential: bool,
    ) -> Result<ActionInstanceAdmissionOutcome, ActionInstanceAdmissionError> {
        let refused = ActionInstanceAdmissionError::FailedPrecondition(refusal);
        request.budget_already_reserved = true;
        match ActionInstanceAdmission::new(self.sekai.runtime(), None)
            .with_proposal(Some(self.proposal_port()))
            .with_tenant(tenant)
            .with_machine_credential(machine_credential)
            .with_budget_refused(true)
            .admit(request, actor, now_ms)
        {
            // Another attempt committed this operation first; answer it.
            Ok(outcome) if outcome.replay => Ok(outcome),
            // A store failure: the denial may not be recorded, so say so.
            Err(error @ ActionInstanceAdmissionError::Internal(_)) => Err(error),
            // Recorded as denied, or refused before recording (a freeze, a
            // missing clearance): answer with the budget refusal.
            _ => Err(refused),
        }
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
        let next = OperationReservation {
            status: RESERVATION_RELEASED.into(),
            updated_at_ms: now_ms,
            incurred_usage: 0,
            ..reservation.clone()
        };
        self.settle(&next)
    }

    /// Store `next` for a pending reservation and refund its charge in one
    /// store write, only while the row is pending: racing callers refund once,
    /// and a crash leaves both writes or neither (#1902). The store refunds
    /// into the budget period the charge was reserved in.
    fn settle(
        &self,
        next: &OperationReservation,
    ) -> Result<OperationReservation, ActionInstanceAdmissionError> {
        let refund = self
            .budget
            .as_ref()
            .map(|_| crate::db::chisei_budget::METRIC_TOKENS);
        Ok(self
            .chisei
            .settle_pending_reservation(next, refund)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .unwrap_or_else(|| next.clone()))
    }

    /// A pending reservation whose operation Sekai committed as a budget
    /// denial, recorded by a concurrent attempt after this one reserved. A
    /// budget denial charges nothing: finalize the reservation with no usage,
    /// refunding once however many callers race here, and record the
    /// refusal's receipt (#1902).
    fn settle_budget_denial(
        &self,
        reservation: &OperationReservation,
        commit: &SekaiCommitRef,
        now_ms: i64,
    ) -> Result<OperationReservation, ActionInstanceAdmissionError> {
        // Finalized, not released: retries replay the committed denial
        // instead of being admitted afresh.
        let settled = self.settle(&OperationReservation {
            status: RESERVATION_FINALIZED.into(),
            incurred_usage: 0,
            sekai_instance_id: commit.instance_id.clone(),
            sekai_status: commit.status.clone(),
            updated_at_ms: now_ms,
            ..reservation.clone()
        })?;
        if self.distinct_stores {
            self.write_decision_receipt(&settled, Some(&commit.marking), now_ms)?;
        }
        Ok(settled)
    }

    /// Whether Sekai committed `operation_id` as a budget denial.
    fn committed_budget_denial(
        &self,
        operation_id: &str,
    ) -> Result<bool, ActionInstanceAdmissionError> {
        Ok(self
            .sekai
            .runtime()
            .get_action_instance_by_operation_id(operation_id)
            .map_err(ActionInstanceAdmissionError::Internal)?
            .is_some_and(|instance| instance.budget_decision == "budget_exceeded"))
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
            Ok(Some(commit)) if self.committed_budget_denial(&reservation.operation_id)? => {
                self.settle_budget_denial(reservation, &commit, now_ms)
            }
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
        let reserved = match self.try_reserve(&request, actor, now_ms)? {
            Ok(reserved) => reserved,
            Err(refusal) => {
                return self.record_budget_refusal(
                    request,
                    refusal,
                    actor,
                    now_ms,
                    tenant,
                    machine_credential,
                );
            }
        };
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
        if reserved.is_pending() && outcome.instance.budget_decision == "budget_exceeded" {
            self.settle_budget_denial(&reserved, &commit, now_ms)?;
        } else if reserved.is_pending() {
            self.finalize(&reserved, Some(&commit), now_ms)?;
        } else {
            self.repair_replayed(&reserved, &commit, now_ms)?;
        }
        Ok(outcome)
    }

    /// A replay reached a finalized or adopted reservation, and Sekai matched
    /// the retry to its commit. On split stores, give a recorded budget
    /// refusal its Chisei receipt. Only where no live reservation exists: a
    /// live one, possibly a concurrent attempt's charge, keeps its row and
    /// receipt. No reservation row is written, so none can be overwritten;
    /// retries keep adopting the Sekai outcome without charging (#1871).
    fn repair_replayed(
        &self,
        reserved: &OperationReservation,
        commit: &SekaiCommitRef,
        now_ms: i64,
    ) -> Result<(), ActionInstanceAdmissionError> {
        if !self.distinct_stores {
            return Ok(());
        }
        let internal = ActionInstanceAdmissionError::Internal;
        let live = self
            .chisei
            .get_operation_reservation(&reserved.namespace, &reserved.operation_id)
            .map_err(internal)?
            .is_some_and(|row| row.status != RESERVATION_RELEASED);
        if live
            || self
                .chisei
                .get_operation_receipt(&reserved.operation_id)
                .map_err(internal)?
                .is_some_and(|receipt| receipt_reflects(&receipt, reserved))
        {
            return Ok(());
        }
        self.write_decision_receipt(reserved, Some(&commit.marking), now_ms)
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

/// Whether a reservation receipt already records `reservation` as it stands:
/// its status and Sekai instance. A receipt left by an earlier pending or
/// released attempt does not (#1871).
fn receipt_reflects(receipt: &OperationReceipt, reservation: &OperationReservation) -> bool {
    receipt.events.iter().any(|event| {
        event.attributes.get("reservation_status") == Some(&reservation.status)
            && event
                .attributes
                .get("sekai_commit_instance_id")
                .map_or(reservation.sekai_instance_id.is_empty(), |id| {
                    id == &reservation.sekai_instance_id
                })
    })
}

/// How both budget stores word exhaustion (`budget exceeded at <scope>: ...`).
const BUDGET_EXHAUSTED: &str = "budget exceeded at ";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::budget::PeriodType;
    use crate::sekai::governed_action_type::{EFFECT_KIND_RUNTIME_DISPATCH, GovernedActionType};
    use tempfile::tempdir;

    /// A time `offset` ms after this test run began. Budget periods follow
    /// the wall clock, so tests that refund a charge use real times.
    fn at(offset: i64) -> i64 {
        static START: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
        *START.get_or_init(|| chrono::Utc::now().timestamp_millis()) + offset
    }

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
            agent_turn: None,
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

        let first = clerk.reserve(&payout("op-pay-1"), "alice", at(10)).unwrap();
        assert_eq!(
            first.budget_subject,
            "action:governed:treasury/project:acme/agent:alice"
        );
        assert!(matches!(
            clerk.reserve(&payout("op-pay-2"), "alice", at(11)),
            Err(ActionInstanceAdmissionError::FailedPrecondition(_))
        ));
        // The namespace budget is still unspent.
        let unscoped = clerk
            .reserve(&request("op-dispatch"), "alice", at(12))
            .unwrap();
        assert_eq!(
            unscoped.budget_subject,
            "action:governed/project:acme/agent:alice"
        );
    }

    /// A type can cap total spend per turn (#1859): the turn parameter
    /// segments the budget and the amount parameter is what each admission
    /// charges. Spends fill the turn's cap, the next is refused naming that
    /// budget, and the next turn starts from zero.
    #[test]
    fn a_per_turn_spend_cap_admits_up_to_the_cap_and_refuses_the_next() {
        let (sekai, chisei) = dest_pair();
        sekai
            .runtime()
            .put_governed_action_type(
                GovernedActionType {
                    namespace: "acme".into(),
                    type_id: "spend".into(),
                    version: "1".into(),
                    description: "spend gold".into(),
                    parameter_schema_json: r#"{"type":"object","properties":{"turn":{"type":"string"},"amount":{"type":"integer","minimum":0}},"required":["turn","amount"],"additionalProperties":false}"#.into(),
                    allowed_effect_kinds: vec![EFFECT_KIND_RUNTIME_DISPATCH.into()],
                    enabled: true,
                    budget_work_unit_parameter: "turn".into(),
                    budget_amount_parameter: "amount".into(),
                    ..Default::default()
                },
                "operator",
                1,
            )
            .unwrap();
        let turn =
            |turn: &str| format!("action:governed/project:acme/agent:alice/work_unit:{turn}");
        let budget = Arc::new(BudgetTracker::new(chisei.clone()));
        for name in ["turn-1", "turn-2"] {
            budget
                .set_limit(&turn(name), 10, PeriodType::Daily)
                .unwrap();
        }
        let clerk = CrossStoreAdmission::new(chisei, sekai, Some(budget.clone()));
        let spend = |operation_id: &str, turn: &str, amount: i32| ActionInstanceAdmissionRequest {
            type_id: "spend".into(),
            parameters_json: format!(r#"{{"turn":"{turn}","amount":{amount}}}"#),
            ..request(operation_id)
        };

        for (operation_id, amount, offset) in [("op-1", 4, 10), ("op-2", 6, 11)] {
            let admitted = clerk
                .admit(
                    spend(operation_id, "turn-1", amount),
                    "alice",
                    at(offset),
                    "",
                    false,
                )
                .unwrap();
            assert_eq!(admitted.instance.status, "admitted");
        }
        assert_eq!(budget.get_usage(&turn("turn-1")).tokens_used, 10);
        let refused = clerk
            .admit(spend("op-3", "turn-1", 1), "alice", at(12), "", false)
            .unwrap_err();
        assert!(
            matches!(&refused, ActionInstanceAdmissionError::FailedPrecondition(reason) if reason.contains(&turn("turn-1"))),
            "{refused:?}"
        );
        assert_eq!(budget.get_usage(&turn("turn-1")).tokens_used, 10);

        let next_turn = clerk
            .admit(spend("op-4", "turn-2", 7), "alice", at(13), "", false)
            .unwrap();
        assert_eq!(next_turn.instance.status, "admitted");
        assert_eq!(budget.get_usage(&turn("turn-2")).tokens_used, 7);
    }

    /// On split stores a budget refusal leaves the same trace as on the
    /// combined layout: a denied decision naming the budget, with no usage
    /// charged, and a retry replays it without charging (#1871).
    #[test]
    fn budget_refusal_is_recorded_like_other_refusals() {
        let (sekai, chisei) = dest_pair();
        seed_type(&sekai);
        let budget = Arc::new(BudgetTracker::new(chisei.clone()));
        budget
            .set_limit("action:governed", 1, PeriodType::Daily)
            .unwrap();
        let clerk = CrossStoreAdmission::new(chisei, sekai, Some(budget.clone()));
        let used = || budget.get_usage("action:governed").tokens_used;

        let admitted = clerk
            .admit(request("op-1"), "alice", at(10), "", false)
            .unwrap();
        assert_eq!(admitted.instance.status, "admitted");
        let refused = clerk
            .admit(request("op-2"), "alice", at(11), "", false)
            .unwrap_err();
        assert!(
            matches!(refused, ActionInstanceAdmissionError::FailedPrecondition(_)),
            "{refused:?}"
        );
        assert_eq!(used(), 1);

        let decisions = clerk
            .sekai
            .runtime()
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("submit_action_instance".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        let denied = decisions
            .iter()
            .find(|decision| decision.reason == "action_instance_budget_denied")
            .unwrap_or_else(|| panic!("no budget denial in {decisions:?}"));
        assert_eq!(denied.outcome, "denied");
        assert!(
            denied.evidence["deny_reason"].contains("action:governed/project:acme/agent:alice"),
            "{denied:?}"
        );

        let _ = clerk.admit(request("op-2"), "alice", at(12), "", false);
        assert_eq!(used(), 1);
    }

    /// A budget failure that is not exhaustion, here a scope pinned to another
    /// site, stays retryable: nothing is recorded or charged (#1871).
    #[test]
    fn a_budget_routing_failure_is_not_recorded_as_a_denial() {
        let (sekai, chisei) = dest_pair();
        seed_type(&sekai);
        let budget = Arc::new(BudgetTracker::with_topology(
            chisei.clone(),
            crate::chisei::budget::BudgetTopologyConfig {
                mode: crate::chisei::budget::BudgetTopologyMode::RegionalPinned,
                site_id: "this-site".into(),
                partition_simulated: false,
            },
        ));
        budget
            .set_limit_scoped(
                "action:governed",
                crate::db::chisei_budget::METRIC_TOKENS,
                8,
                PeriodType::Daily,
                "another-site",
                "",
            )
            .unwrap();
        let clerk = CrossStoreAdmission::new(chisei, sekai, Some(budget));

        let error = clerk
            .admit(request("op-pinned"), "alice", at(10), "", false)
            .unwrap_err();
        assert!(format!("{error:?}").contains("another-site"), "{error:?}");
        assert!(
            clerk
                .sekai
                .runtime()
                .get_action_instance_by_operation_id("op-pinned")
                .unwrap()
                .is_none()
        );
        assert!(
            clerk
                .chisei
                .get_operation_reservation("acme", "op-pinned")
                .unwrap()
                .is_none()
        );
    }

    /// A budget refusal Sekai recorded before its reservation write was lost
    /// is adopted on retry: replayed, and charged nothing (#1871).
    #[test]
    fn a_recorded_refusal_without_a_reservation_is_not_charged_on_retry() {
        let (clerk, budget) = clerk_with_budget();
        // An earlier attempt left a released reservation behind.
        let earlier = clerk.reserve(&request("op-lost"), "alice", at(5)).unwrap();
        clerk.release(&earlier, at(6)).unwrap();
        let mut lost = request("op-lost");
        lost.budget_already_reserved = true;
        let recorded = ActionInstanceAdmission::new(clerk.sekai.runtime(), None)
            .with_budget_refused(true)
            .admit(lost, "alice", at(10))
            .unwrap();
        assert_eq!(recorded.instance.status, "denied");

        // A changed retry is refused and leaves nothing behind that would
        // block the original.
        let changed = ActionInstanceAdmissionRequest {
            parameters_json: r#"{"runtime":"other"}"#.into(),
            ..request("op-lost")
        };
        assert!(clerk.admit(changed, "alice", at(11), "", false).is_err());
        let retried = clerk
            .admit(request("op-lost"), "alice", at(12), "", false)
            .unwrap();
        assert!(retried.replay);
        assert_eq!(retried.instance.instance_id, recorded.instance.instance_id);
        assert_eq!(budget.get_usage("action:governed").tokens_used, 0);
        // The retry wrote the refusal's receipt over the earlier attempt's
        // stale one, and left the released row with nothing charged.
        let receipt = clerk
            .chisei
            .get_operation_receipt("op-lost")
            .unwrap()
            .unwrap();
        assert_eq!(
            receipt.events[0].attributes["reservation_status"],
            RESERVATION_FINALIZED
        );
        assert_eq!(
            receipt.events[0].attributes["sekai_commit_instance_id"],
            recorded.instance.instance_id
        );
        let row = clerk
            .chisei
            .get_operation_reservation("acme", "op-lost")
            .unwrap()
            .unwrap();
        assert_eq!(row.status, RESERVATION_RELEASED);
        assert_eq!(row.incurred_usage, 0);
    }

    /// Only a denial is adopted without charge: admitted work whose
    /// reservation was released is charged again on retry, as before (#1871).
    #[test]
    fn a_released_admission_is_charged_again_on_retry() {
        let (clerk, budget) = clerk_with_budget();
        let used = || budget.get_usage("action:governed").tokens_used;
        let reserved = clerk.reserve(&request("op-late"), "alice", at(5)).unwrap();
        let admitted = clerk
            .submit_sekai(request("op-late"), "alice", at(6), "", false)
            .unwrap();
        assert_eq!(admitted.instance.status, "admitted");
        clerk.release(&reserved, at(7)).unwrap();
        assert_eq!(used(), 0);

        let replayed = clerk
            .admit(request("op-late"), "alice", at(8), "", false)
            .unwrap();
        assert!(replayed.replay);
        assert_eq!(used(), 1);
    }

    /// `op-race` reserved one unit, then a concurrent attempt recorded it as
    /// a budget denial. Another operation's unit stays charged throughout, so
    /// a double refund would show below it.
    fn raced_budget_denial() -> (
        CrossStoreAdmission,
        Arc<BudgetTracker>,
        OperationReservation,
    ) {
        let (clerk, budget) = clerk_with_budget();
        clerk
            .admit(request("op-other"), "alice", at(1), "", false)
            .unwrap();
        let reserved = clerk.reserve(&request("op-race"), "bob", at(5)).unwrap();
        assert_eq!(budget.get_usage("action:governed").tokens_used, 2);
        let mut refused = request("op-race");
        refused.budget_already_reserved = true;
        ActionInstanceAdmission::new(clerk.sekai.runtime(), None)
            .with_budget_refused(true)
            .admit(refused, "alice", at(6))
            .unwrap();
        (clerk, budget, reserved)
    }

    /// The attempt that reserved gets its charge back when it replays the
    /// concurrent budget denial (#1902).
    #[test]
    fn replaying_a_concurrent_budget_denial_refunds_the_reservation() {
        let (clerk, budget, _) = raced_budget_denial();
        let replayed = clerk
            .admit(request("op-race"), "bob", at(7), "", false)
            .unwrap();
        assert!(replayed.replay);
        assert_eq!(budget.get_usage("action:governed").tokens_used, 1);
        let row = clerk
            .chisei
            .get_operation_reservation("acme", "op-race")
            .unwrap()
            .unwrap();
        assert_eq!(row.status, RESERVATION_FINALIZED);
        assert_eq!(row.incurred_usage, 0);
    }

    /// A reacquired reservation records the release it follows, so replaying
    /// a concurrent budget denial refunds its own charge (#1902).
    #[test]
    fn a_reacquired_reservation_refunds_its_own_charge() {
        let (clerk, budget) = clerk_with_budget();
        let used = || budget.get_usage("action:governed").tokens_used;
        clerk
            .admit(request("op-other"), "alice", at(1), "", false)
            .unwrap();
        let first = clerk.reserve(&request("op-again"), "bob", at(5)).unwrap();
        clerk.release(&first, at(6)).unwrap();
        assert_eq!(used(), 1);
        let again = clerk.reserve(&request("op-again"), "bob", at(7)).unwrap();
        assert_eq!(again.charge_key, format!("op-again:reacquire:{}", at(6)));
        assert_eq!(used(), 2);
        let mut refused = request("op-again");
        refused.budget_already_reserved = true;
        ActionInstanceAdmission::new(clerk.sekai.runtime(), None)
            .with_budget_refused(true)
            .admit(refused, "alice", at(8))
            .unwrap();

        let replayed = clerk
            .admit(request("op-again"), "bob", at(9), "", false)
            .unwrap();
        assert!(replayed.replay);
        assert_eq!(used(), 1);
    }

    /// A stale release of an earlier acquisition leaves a later one of the
    /// same operation pending and charged (#1902).
    #[test]
    fn a_stale_release_does_not_settle_a_later_acquisition() {
        let (clerk, budget) = clerk_with_budget();
        let first = clerk.reserve(&request("op-gen"), "bob", at(5)).unwrap();
        clerk.release(&first, at(6)).unwrap();
        let again = clerk.reserve(&request("op-gen"), "bob", at(7)).unwrap();
        assert_eq!(budget.get_usage("action:governed").tokens_used, 1);

        clerk.release(&first, at(8)).unwrap();
        let row = clerk
            .chisei
            .get_operation_reservation("acme", "op-gen")
            .unwrap()
            .unwrap();
        assert_eq!(row.status, RESERVATION_PENDING);
        assert_eq!(row.charge_key, again.charge_key);
        assert_eq!(row.incurred_usage, 1);
        assert_eq!(budget.get_usage("action:governed").tokens_used, 1);
    }

    /// Racing releases of one reservation refund it once (#1902).
    #[test]
    fn releasing_one_reservation_twice_refunds_once() {
        let (clerk, budget, reserved) = raced_budget_denial();
        std::thread::scope(|scope| {
            for offset in [7, 8] {
                let (clerk, reserved) = (&clerk, &reserved);
                scope.spawn(move || clerk.release(reserved, at(offset)).unwrap());
            }
        });
        assert_eq!(budget.get_usage("action:governed").tokens_used, 1);
    }

    /// Reconciliation that reaches the reservation first refunds it, and the
    /// replay after it refunds nothing more (#1902).
    #[test]
    fn reconciliation_refunds_a_concurrent_budget_denial_once() {
        let (clerk, budget, _) = raced_budget_denial();
        clerk.reconcile_pending(at(7)).unwrap();
        assert_eq!(budget.get_usage("action:governed").tokens_used, 1);
        let replayed = clerk
            .admit(request("op-race"), "bob", at(8), "", false)
            .unwrap();
        assert!(replayed.replay);
        assert_eq!(budget.get_usage("action:governed").tokens_used, 1);
    }

    #[test]
    fn crash_after_reserve_keeps_pending() {
        let (clerk, _) = clerk_with_budget();
        let reserved = clerk
            .reserve(&request("op-reserve"), "alice", at(10))
            .unwrap();
        assert_eq!(reserved.status, RESERVATION_PENDING);
        assert!(
            clerk
                .sekai
                .runtime()
                .get_action_instance_by_operation_id("op-reserve")
                .unwrap()
                .is_none()
        );
        let again = clerk.reconcile_one(&reserved, at(11)).unwrap();
        assert_eq!(again.status, RESERVATION_PENDING);
    }

    #[test]
    fn crash_after_commit_reconcile_finalizes() {
        let (clerk, _) = clerk_with_budget();
        let req = request("op-commit");
        let _reserved = clerk.reserve(&req, "alice", at(10)).unwrap();
        let outcome = clerk.submit_sekai(req, "alice", at(11), "", false).unwrap();
        assert_eq!(outcome.instance.status, "admitted");
        let still = clerk
            .chisei
            .get_operation_reservation("acme", "op-commit")
            .unwrap()
            .unwrap();
        assert_eq!(still.status, RESERVATION_PENDING);
        let finalized = clerk.reconcile_one(&still, at(12)).unwrap();
        assert_eq!(finalized.status, RESERVATION_FINALIZED);
        assert_eq!(finalized.sekai_instance_id, outcome.instance.instance_id);
        assert_ne!(finalized.sekai_status, "rejected");
    }

    #[test]
    fn duplicate_identity_is_idempotent_and_digest_mismatch_fails_closed() {
        let (clerk, _) = clerk_with_budget();
        let first = clerk.reserve(&request("op-dup"), "alice", at(10)).unwrap();
        let replay = clerk.reserve(&request("op-dup"), "alice", at(11)).unwrap();
        assert_eq!(first.request_digest, replay.request_digest);
        assert_eq!(replay.status, RESERVATION_PENDING);
        let mut conflict = request("op-dup");
        conflict.parameters_json = r#"{"runtime":"other"}"#.into();
        let error = clerk.reserve(&conflict, "alice", at(12)).unwrap_err();
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
        let error = clerk
            .admit(invalid, "alice", at(10), "", false)
            .unwrap_err();
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
            .admit(request("op-valid"), "alice", at(11), "", false)
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
            .admit(request("op-frozen"), "alice", at(10), "", false)
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
            .admit(request("op-frozen"), "alice", at(20), "", false)
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
        let reserved = clerk.reserve(&request("op-deny"), "alice", at(10)).unwrap();
        let used_after_reserve = budget.get_usage("action:governed").tokens_used;
        assert!(used_after_reserve >= 1);
        clerk.finalize(&reserved, None, at(11)).unwrap();
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
        let reserved = clerk
            .reserve(&request("op-timeout"), "alice", at(10))
            .unwrap();
        let after = clerk.reconcile_one(&reserved, at(12)).unwrap();
        assert_eq!(after.status, RESERVATION_PENDING);
        let released = clerk.reconcile_one(&reserved, at(20)).unwrap();
        assert_eq!(released.status, RESERVATION_RELEASED);
    }

    #[test]
    fn admit_writes_plane_specific_receipts_without_copying_bodies() {
        let (clerk, _) = clerk_with_budget();
        assert!(clerk.distinct_stores());
        let outcome = clerk
            .admit(request("op-receipts"), "alice", at(10), "", false)
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
            .admit(request("op-shared"), "alice", at(10), "", false)
            .unwrap();
        let receipt = clerk
            .chisei
            .get_operation_receipt("op-shared")
            .unwrap()
            .expect("shared receipt");
        assert_eq!(receipt.operation_class, "governed_action_instance");
    }
}
