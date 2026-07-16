//! Human-readable projections of canonical governed-operation receipts.

use crate::chisei::receipt::{
    GovernedReference, OperationReceipt, OperationReceiptEvent, ReceiptSurface, UncoveredSurface,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPERATION_REPORT_VERSION: &str = "operation.report/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceClaims {
    pub evidence_complete: bool,
    pub integrity: ClaimState,
    pub policy_compliance: ClaimState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    NotVerified,
    Verified,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEvent {
    pub event_id: String,
    pub parent_event_id: Option<String>,
    pub timestamp_ms: i64,
    pub kind: String,
    pub actor: String,
    pub attributes: BTreeMap<String, String>,
    pub references: Vec<GovernedReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReport {
    pub version: String,
    pub source_receipt_version: String,
    pub operation_id: String,
    pub parent_operation_id: Option<String>,
    pub namespace: String,
    pub operation_class: String,
    pub initiating_actor: String,
    pub schema_version: String,
    pub policy_version: String,
    pub started_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub duration_ms: Option<i64>,
    pub claims: AssuranceClaims,
    pub sections: BTreeMap<String, Vec<ReportEvent>>,
    pub missing_surfaces: Vec<ReceiptSurface>,
    pub uncovered_surfaces: Vec<UncoveredSurface>,
    pub structural_errors: Vec<String>,
}

impl OperationReport {
    pub fn from_receipt(receipt: &OperationReceipt) -> Self {
        let completeness = receipt.completeness();
        let mut sections = BTreeMap::<String, Vec<ReportEvent>>::new();
        for event in causally_ordered_events(receipt) {
            sections
                .entry(event.surface.as_str().into())
                .or_default()
                .push(ReportEvent {
                    event_id: event.event_id.clone(),
                    parent_event_id: event.parent_event_id.clone(),
                    timestamp_ms: event.timestamp_ms,
                    kind: event.kind.as_str().into(),
                    actor: event.actor.clone(),
                    attributes: event.attributes.clone(),
                    references: event.references.clone(),
                });
        }
        let duration_ms = receipt
            .completed_at_ms
            .map(|end| end.saturating_sub(receipt.started_at_ms));
        let mut structural_errors = completeness.errors;
        if duration_ms.is_some_and(|duration| duration < 0) {
            structural_errors.push("completed_at_ms precedes started_at_ms".into());
        }
        Self {
            version: OPERATION_REPORT_VERSION.into(),
            source_receipt_version: receipt.version.clone(),
            operation_id: receipt.operation_id.clone(),
            parent_operation_id: receipt.parent_operation_id.clone(),
            namespace: receipt.namespace.clone(),
            operation_class: receipt.operation_class.clone(),
            initiating_actor: receipt.initiating_actor.clone(),
            schema_version: receipt.schema_version.clone(),
            policy_version: receipt.policy_version.clone(),
            started_at_ms: receipt.started_at_ms,
            completed_at_ms: receipt.completed_at_ms,
            duration_ms: duration_ms.filter(|duration| *duration >= 0),
            claims: AssuranceClaims {
                evidence_complete: completeness.complete && structural_errors.is_empty(),
                integrity: ClaimState::NotVerified,
                policy_compliance: ClaimState::NotVerified,
            },
            sections,
            missing_surfaces: completeness.missing_surfaces,
            uncovered_surfaces: receipt.uncovered_surfaces.clone(),
            structural_errors,
        }
    }
}

fn causally_ordered_events(receipt: &OperationReceipt) -> Vec<&OperationReceiptEvent> {
    let by_id = receipt
        .events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect::<BTreeMap<_, _>>();
    let mut events = receipt.events.iter().collect::<Vec<_>>();
    events.sort_by_cached_key(|event| {
        let mut depth = 0usize;
        let mut parent = event.parent_event_id.as_deref();
        let mut remaining = by_id.len();
        while let Some(parent_id) = parent {
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            depth += 1;
            parent = by_id
                .get(parent_id)
                .and_then(|parent| parent.parent_event_id.as_deref());
        }
        (depth, event.timestamp_ms, event.event_id.as_str())
    });
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind, ReceiptSurface,
    };

    fn event(id: &str, parent: Option<&str>, kind: ReceiptEventKind) -> OperationReceiptEvent {
        OperationReceiptEvent {
            event_id: id.into(),
            operation_id: "op-1".into(),
            parent_event_id: parent.map(str::to_string),
            timestamp_ms: 1,
            kind,
            surface: kind.surface(),
            actor: "agent".into(),
            references: vec![],
            attributes: BTreeMap::new(),
        }
    }
    fn receipt() -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "team-a".into(),
            operation_class: "analysis".into(),
            initiating_actor: "operator".into(),
            schema_version: "schema/v1".into(),
            policy_version: "policy/v1".into(),
            started_at_ms: 10,
            completed_at_ms: Some(25),
            events: vec![
                event("outcome", Some("intent"), ReceiptEventKind::OutcomeRecorded),
                event("intent", None, ReceiptEventKind::IntentRecorded),
            ],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        }
    }

    #[test]
    fn report_is_a_receipt_projection_with_separate_assurance_claims() {
        let report = OperationReport::from_receipt(&receipt());
        assert_eq!(report.source_receipt_version, OPERATION_RECEIPT_VERSION);
        assert_eq!(report.duration_ms, Some(15));
        assert_eq!(report.claims.integrity, ClaimState::NotVerified);
        assert_eq!(report.claims.policy_compliance, ClaimState::NotVerified);
        assert!(!report.missing_surfaces.is_empty());
        assert_eq!(
            report.sections[ReceiptSurface::Intent.as_str()][0].event_id,
            "intent"
        );
    }

    #[test]
    fn uncovered_surfaces_prevent_completeness_claims() {
        let mut source = receipt();
        source.events.extend([
            event("policy", Some("intent"), ReceiptEventKind::PolicyDecided),
            event("route", Some("policy"), ReceiptEventKind::RouteSelected),
            event("budget", Some("route"), ReceiptEventKind::BudgetDecided),
        ]);
        assert!(
            OperationReport::from_receipt(&source)
                .claims
                .evidence_complete
        );
        source.uncovered_surfaces.push(UncoveredSurface {
            surface: ReceiptSurface::Action,
            reason: "external action was not governed".into(),
        });
        let report = OperationReport::from_receipt(&source);
        assert!(!report.claims.evidence_complete);
    }

    #[test]
    fn inverted_timestamps_are_reported_instead_of_rendered_as_negative_duration() {
        let mut source = receipt();
        source.completed_at_ms = Some(5);
        let report = OperationReport::from_receipt(&source);
        assert_eq!(report.duration_ms, None);
        assert!(
            report
                .structural_errors
                .iter()
                .any(|error| error.contains("precedes"))
        );
    }
}
