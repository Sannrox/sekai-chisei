use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use tonic::Status;

use crate::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    ReceiptSurface, UncoveredSurface,
};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::capability;

/// Owns the durable receipt lifecycle for one catalog-attributed invocation.
/// Transport metadata and capability visibility remain the caller's concern.
pub(super) struct CatalogInvocation<'a> {
    db: &'a RuntimeDb,
    operation_id: String,
    namespace: String,
    actor: String,
    capability_name: String,
    catalog_version: Option<String>,
    policy_decision: Option<String>,
    budget_decision: Option<String>,
    finalized: bool,
}

impl<'a> CatalogInvocation<'a> {
    pub(super) fn begin(
        db: &'a RuntimeDb,
        operation_id: String,
        namespace: &str,
        actor: String,
        capability_name: String,
        catalog_version: Option<String>,
    ) -> Result<Self, Status> {
        record(
            db,
            &operation_id,
            namespace,
            &actor,
            &capability_name,
            catalog_version.as_deref(),
            "pending",
            "invocation_started",
            true,
        )?;
        Ok(Self {
            db,
            operation_id,
            namespace: namespace.to_string(),
            actor,
            capability_name,
            catalog_version,
            policy_decision: None,
            budget_decision: None,
            finalized: false,
        })
    }

    pub(super) fn record_refusal(
        db: &RuntimeDb,
        operation_id: &str,
        namespace: &str,
        actor: &str,
        capability_name: &str,
        catalog_version: Option<&str>,
        outcome: &str,
    ) -> Result<(), Status> {
        record(
            db,
            operation_id,
            namespace,
            actor,
            capability_name,
            catalog_version,
            "refuse",
            outcome,
            true,
        )
    }

    #[cfg(test)]
    pub(super) fn mark_policy_decided(&mut self, decision: &str) {
        self.policy_decision = Some(decision.to_string());
    }

    #[cfg(test)]
    pub(super) fn mark_budget_decided(&mut self, decision: &str) {
        self.budget_decision = Some(decision.to_string());
    }

    pub(super) fn finalize(&mut self, decision: &str, outcome: &str) -> Result<(), Status> {
        record(
            self.db,
            &self.operation_id,
            &self.namespace,
            &self.actor,
            &self.capability_name,
            self.catalog_version.as_deref(),
            decision,
            outcome,
            false,
        )?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for CatalogInvocation<'_> {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        let budget_outcome = self
            .budget_decision
            .as_deref()
            .map(|decision| format!("invocation_failed_after_budget:{decision}"));
        let (decision, outcome) = if let Some(outcome) = budget_outcome.as_deref() {
            (self.policy_decision.as_deref().unwrap_or("allow"), outcome)
        } else {
            self.policy_decision
                .as_deref()
                .map(|decision| (decision, "invocation_failed_after_policy"))
                .unwrap_or(("refuse", "invocation_failed"))
        };
        let _ = record(
            self.db,
            &self.operation_id,
            &self.namespace,
            &self.actor,
            &self.capability_name,
            self.catalog_version.as_deref(),
            decision,
            outcome,
            false,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    db: &RuntimeDb,
    operation_id: &str,
    namespace: &str,
    actor: &str,
    capability_name: &str,
    catalog_version: Option<&str>,
    decision: &str,
    outcome: &str,
    insert_only: bool,
) -> Result<(), Status> {
    let now = now_millis();
    let started_at_ms = if insert_only {
        now
    } else {
        db.get_operation_receipt(operation_id)
            .map_err(Status::internal)?
            .map(|receipt| receipt.started_at_ms)
            .unwrap_or(now)
    };
    let event = |suffix: &str, parent: Option<&str>, kind: ReceiptEventKind, attributes| {
        OperationReceiptEvent {
            event_id: format!("{operation_id}:{suffix}"),
            operation_id: operation_id.into(),
            parent_event_id: parent.map(|value| format!("{operation_id}:{value}")),
            timestamp_ms: now,
            surface: kind.surface(),
            kind,
            actor: actor.into(),
            references: Vec::new(),
            attributes,
        }
    };
    let attributes =
        |key: &str, value: &str| BTreeMap::from([(key.to_string(), value.to_string())]);
    let outcome_attributes = || {
        if let Some(approval_id) = outcome.strip_prefix("approval_required:") {
            BTreeMap::from([
                ("outcome".into(), "approval_required".into()),
                ("approval_id".into(), approval_id.into()),
            ])
        } else {
            attributes("outcome", outcome)
        }
    };
    let mut intent_attributes = attributes("capability", capability_name);
    if let Some(catalog_version) = catalog_version.filter(|value| !value.trim().is_empty()) {
        intent_attributes.insert("reported_catalog_version".into(), catalog_version.into());
    }
    let mut intent = event(
        "intent",
        None,
        ReceiptEventKind::IntentRecorded,
        intent_attributes,
    );
    intent.timestamp_ms = started_at_ms;
    let (completed_at_ms, events, uncovered_surfaces) = if insert_only && decision == "pending" {
        (None, vec![intent], Vec::new())
    } else if decision == "refuse" {
        (
            Some(now),
            vec![
                intent,
                event(
                    "outcome",
                    Some("intent"),
                    ReceiptEventKind::OutcomeRecorded,
                    outcome_attributes(),
                ),
            ],
            [
                ReceiptSurface::Policy,
                ReceiptSurface::Routing,
                ReceiptSurface::Budget,
            ]
            .into_iter()
            .map(|surface| UncoveredSurface {
                surface,
                reason: "invocation failed before this decision point".into(),
            })
            .collect(),
        )
    } else if let Some(budget_decision) = outcome.strip_prefix("invocation_failed_after_budget:") {
        (
            Some(now),
            vec![
                intent,
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    attributes("decision", decision),
                ),
                event(
                    "routing",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    attributes("route", "native"),
                ),
                event(
                    "budget",
                    Some("routing"),
                    ReceiptEventKind::BudgetDecided,
                    attributes("decision", budget_decision),
                ),
                event(
                    "outcome",
                    Some("budget"),
                    ReceiptEventKind::OutcomeRecorded,
                    attributes("outcome", "invocation_failed_after_budget"),
                ),
            ],
            Vec::new(),
        )
    } else if outcome == "invocation_failed_after_policy" {
        (
            Some(now),
            vec![
                intent,
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    attributes("decision", decision),
                ),
                event(
                    "routing",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    attributes("route", "native"),
                ),
                event(
                    "outcome",
                    Some("routing"),
                    ReceiptEventKind::OutcomeRecorded,
                    outcome_attributes(),
                ),
            ],
            vec![UncoveredSurface {
                surface: ReceiptSurface::Budget,
                reason: "invocation failed before budget decision".into(),
            }],
        )
    } else {
        let budget_decision = match outcome.split_once(':').map_or(outcome, |value| value.0) {
            "dry_run" => "not_applicable_dry_run",
            "approval_required" => "deferred_pending_approval",
            "denied" | "capability_unavailable" => "not_applicable_policy_denied",
            _ => "checked_at_invocation",
        };
        (
            Some(now),
            vec![
                intent,
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    attributes("decision", decision),
                ),
                event(
                    "routing",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    attributes("route", "native"),
                ),
                event(
                    "budget",
                    Some("routing"),
                    ReceiptEventKind::BudgetDecided,
                    attributes("decision", budget_decision),
                ),
                event(
                    "outcome",
                    Some("budget"),
                    ReceiptEventKind::OutcomeRecorded,
                    outcome_attributes(),
                ),
            ],
            Vec::new(),
        )
    };
    let receipt = OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.into(),
        parent_operation_id: None,
        namespace: namespace.into(),
        operation_class: "catalog_invocation".into(),
        initiating_actor: actor.into(),
        schema_version: capability::CONTRACT_VERSION.into(),
        policy_version: "live_invocation_check".into(),
        started_at_ms,
        completed_at_ms,
        events,
        uncovered_surfaces,
        reporter_grants: Vec::new(),
        ontology_digest: None,
    };
    if insert_only {
        db.insert_operation_receipt(&receipt).map_err(|error| {
            if error.contains("UNIQUE constraint failed") {
                Status::already_exists("operation receipt already exists")
            } else {
                Status::internal(error)
            }
        })
    } else {
        db.put_operation_receipt(&receipt).map_err(Status::internal)
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::db::sekai::SekaiDb;

    fn database() -> RuntimeDb {
        RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    #[test]
    fn explicit_completion_records_the_complete_decision_path() {
        let db = database();
        let mut invocation = CatalogInvocation::begin(
            &db,
            "operation-1".into(),
            "project-a",
            "alice".into(),
            "sekai.object.query".into(),
            Some("catalog-v1".into()),
        )
        .unwrap();
        invocation.mark_policy_decided("allow");
        invocation.mark_budget_decided("within_limit");
        invocation.finalize("allow", "completed").unwrap();

        let receipt = db.get_operation_receipt("operation-1").unwrap().unwrap();
        assert!(receipt.completed_at_ms.is_some());
        assert_eq!(
            receipt
                .events
                .iter()
                .map(|event| event.kind)
                .collect::<Vec<_>>(),
            vec![
                ReceiptEventKind::IntentRecorded,
                ReceiptEventKind::PolicyDecided,
                ReceiptEventKind::RouteSelected,
                ReceiptEventKind::BudgetDecided,
                ReceiptEventKind::OutcomeRecorded,
            ]
        );
        assert!(receipt.uncovered_surfaces.is_empty());
    }

    #[test]
    fn dropping_after_policy_records_a_fail_closed_outcome() {
        let db = database();
        {
            let mut invocation = CatalogInvocation::begin(
                &db,
                "operation-2".into(),
                "project-a",
                "alice".into(),
                "sekai.object.query".into(),
                None,
            )
            .unwrap();
            invocation.mark_policy_decided("allow");
        }

        let receipt = db.get_operation_receipt("operation-2").unwrap().unwrap();
        let outcome = receipt.events.last().unwrap();
        assert_eq!(outcome.kind, ReceiptEventKind::OutcomeRecorded);
        assert_eq!(
            outcome.attributes.get("outcome").map(String::as_str),
            Some("invocation_failed_after_policy")
        );
        assert_eq!(receipt.uncovered_surfaces.len(), 1);
        assert_eq!(
            receipt.uncovered_surfaces[0].surface,
            ReceiptSurface::Budget
        );
    }
}
