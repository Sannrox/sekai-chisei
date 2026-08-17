//! Versioned, domain-neutral evidence contracts for governed operations.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const OPERATION_RECEIPT_VERSION: &str = "operation.receipt/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptSurface {
    Intent,
    Context,
    Policy,
    Routing,
    Budget,
    Approval,
    Egress,
    Attempt,
    ModelCall,
    Action,
    Artifact,
    Verification,
    Intervention,
    Outcome,
    Memory,
}

impl ReceiptSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Context => "context",
            Self::Policy => "policy",
            Self::Routing => "routing",
            Self::Budget => "budget",
            Self::Approval => "approval",
            Self::Egress => "egress",
            Self::Attempt => "attempt",
            Self::ModelCall => "model_call",
            Self::Action => "action",
            Self::Artifact => "artifact",
            Self::Verification => "verification",
            Self::Intervention => "intervention",
            Self::Outcome => "outcome",
            Self::Memory => "memory",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptEventKind {
    IntentRecorded,
    ContextGoverned,
    PolicyDecided,
    RouteSelected,
    BudgetDecided,
    ApprovalDecided,
    EgressDecided,
    AttemptStarted,
    ModelCalled,
    ActionPerformed,
    ArtifactProduced,
    VerificationRecorded,
    HumanIntervened,
    OutcomeRecorded,
    MemoryOutcomeRecorded,
}

impl ReceiptEventKind {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim() {
            "intent_recorded" => Self::IntentRecorded,
            "context_governed" => Self::ContextGoverned,
            "policy_decided" => Self::PolicyDecided,
            "route_selected" => Self::RouteSelected,
            "budget_decided" => Self::BudgetDecided,
            "approval_decided" => Self::ApprovalDecided,
            "egress_decided" => Self::EgressDecided,
            "attempt_started" => Self::AttemptStarted,
            "model_called" => Self::ModelCalled,
            "action_performed" => Self::ActionPerformed,
            "artifact_produced" => Self::ArtifactProduced,
            "verification_recorded" => Self::VerificationRecorded,
            "human_intervened" => Self::HumanIntervened,
            "outcome_recorded" => Self::OutcomeRecorded,
            "memory_outcome_recorded" => Self::MemoryOutcomeRecorded,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntentRecorded => "intent_recorded",
            Self::ContextGoverned => "context_governed",
            Self::PolicyDecided => "policy_decided",
            Self::RouteSelected => "route_selected",
            Self::BudgetDecided => "budget_decided",
            Self::ApprovalDecided => "approval_decided",
            Self::EgressDecided => "egress_decided",
            Self::AttemptStarted => "attempt_started",
            Self::ModelCalled => "model_called",
            Self::ActionPerformed => "action_performed",
            Self::ArtifactProduced => "artifact_produced",
            Self::VerificationRecorded => "verification_recorded",
            Self::HumanIntervened => "human_intervened",
            Self::OutcomeRecorded => "outcome_recorded",
            Self::MemoryOutcomeRecorded => "memory_outcome_recorded",
        }
    }

    pub const fn surface(self) -> ReceiptSurface {
        match self {
            Self::IntentRecorded => ReceiptSurface::Intent,
            Self::ContextGoverned => ReceiptSurface::Context,
            Self::PolicyDecided => ReceiptSurface::Policy,
            Self::RouteSelected => ReceiptSurface::Routing,
            Self::BudgetDecided => ReceiptSurface::Budget,
            Self::ApprovalDecided => ReceiptSurface::Approval,
            Self::EgressDecided => ReceiptSurface::Egress,
            Self::AttemptStarted => ReceiptSurface::Attempt,
            Self::ModelCalled => ReceiptSurface::ModelCall,
            Self::ActionPerformed => ReceiptSurface::Action,
            Self::ArtifactProduced => ReceiptSurface::Artifact,
            Self::VerificationRecorded => ReceiptSurface::Verification,
            Self::HumanIntervened => ReceiptSurface::Intervention,
            Self::OutcomeRecorded => ReceiptSurface::Outcome,
            Self::MemoryOutcomeRecorded => ReceiptSurface::Memory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedReference {
    pub kind: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub disclosed_fields: Vec<String>,
    #[serde(default)]
    pub omitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omission_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReceiptEvent {
    pub event_id: String,
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    pub timestamp_ms: i64,
    pub kind: ReceiptEventKind,
    pub surface: ReceiptSurface,
    pub actor: String,
    #[serde(default)]
    pub references: Vec<GovernedReference>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncoveredSurface {
    pub surface: ReceiptSurface,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReporterGrant {
    pub principal: String,
    pub event_kinds: Vec<ReceiptEventKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReceipt {
    pub version: String,
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<String>,
    pub namespace: String,
    pub operation_class: String,
    pub initiating_actor: String,
    pub schema_version: String,
    pub policy_version: String,
    pub started_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_ms: Option<i64>,
    #[serde(default)]
    pub events: Vec<OperationReceiptEvent>,
    #[serde(default)]
    pub uncovered_surfaces: Vec<UncoveredSurface>,
    #[serde(default)]
    pub reporter_grants: Vec<OperationReporterGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ontology_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptCompleteness {
    pub complete: bool,
    pub missing_surfaces: Vec<ReceiptSurface>,
    pub errors: Vec<String>,
}

impl OperationReceipt {
    /// Validate structural completeness without relying on event ordering or
    /// timestamp adjacency. Every event must belong to this operation and have
    /// a causal path back to the single intent event.
    pub fn completeness(&self) -> ReceiptCompleteness {
        let mut errors = Vec::new();
        if self.version != OPERATION_RECEIPT_VERSION {
            errors.push(format!("unsupported receipt version {}", self.version));
        }
        for (field, value) in [
            ("operation_id", self.operation_id.as_str()),
            ("namespace", self.namespace.as_str()),
            ("operation_class", self.operation_class.as_str()),
            ("initiating_actor", self.initiating_actor.as_str()),
            ("schema_version", self.schema_version.as_str()),
            ("policy_version", self.policy_version.as_str()),
        ] {
            if value.trim().is_empty() {
                errors.push(format!("{field} is required"));
            }
        }

        let mut by_id = HashMap::new();
        for event in &self.events {
            if event.operation_id != self.operation_id {
                errors.push(format!(
                    "event {} belongs to operation {}",
                    event.event_id, event.operation_id
                ));
            }
            if event.event_id.trim().is_empty() {
                errors.push("event_id is required".to_string());
                continue;
            }
            if event.surface != event.kind.surface() {
                errors.push(format!(
                    "event {} kind {:?} requires surface {:?}",
                    event.event_id,
                    event.kind,
                    event.kind.surface()
                ));
            }
            if by_id.insert(event.event_id.as_str(), event).is_some() {
                errors.push(format!("duplicate event id {}", event.event_id));
            }
        }

        let intent_ids = self
            .events
            .iter()
            .filter(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .map(|event| event.event_id.as_str())
            .collect::<Vec<_>>();
        if intent_ids.len() != 1 {
            errors.push(format!(
                "receipt requires exactly one intent event, found {}",
                intent_ids.len()
            ));
        }
        let intent_id = intent_ids.first().copied();

        for event in &self.events {
            if Some(event.event_id.as_str()) == intent_id {
                if event.parent_event_id.is_some() {
                    errors.push("intent event must not have a causal parent".to_string());
                }
                continue;
            }
            let mut cursor = event.parent_event_id.as_deref();
            let mut visited = HashSet::new();
            while let Some(parent_id) = cursor {
                if !visited.insert(parent_id) {
                    errors.push(format!("causal cycle at event {}", event.event_id));
                    break;
                }
                if Some(parent_id) == intent_id {
                    break;
                }
                let Some(parent) = by_id.get(parent_id) else {
                    errors.push(format!(
                        "event {} references missing causal parent {}",
                        event.event_id, parent_id
                    ));
                    break;
                };
                cursor = parent.parent_event_id.as_deref();
            }
            if cursor.is_none() {
                errors.push(format!(
                    "event {} has no causal path to intent",
                    event.event_id
                ));
            }
        }

        let covered = self
            .events
            .iter()
            .map(|event| event.surface)
            .collect::<HashSet<_>>();
        let explicitly_uncovered = self
            .uncovered_surfaces
            .iter()
            .map(|entry| entry.surface)
            .collect::<HashSet<_>>();
        let required = [
            ReceiptSurface::Intent,
            ReceiptSurface::Policy,
            ReceiptSurface::Routing,
            ReceiptSurface::Budget,
            ReceiptSurface::Outcome,
        ];
        let missing_surfaces = required
            .into_iter()
            .filter(|surface| !covered.contains(surface))
            .collect::<Vec<_>>();

        if self.completed_at_ms.is_none() {
            errors.push("terminal completion timestamp is missing".to_string());
        }
        for uncovered in &self.uncovered_surfaces {
            if uncovered.reason.trim().is_empty() {
                errors.push(format!(
                    "uncovered {:?} surface requires a reason",
                    uncovered.surface
                ));
            }
        }

        ReceiptCompleteness {
            complete: errors.is_empty()
                && missing_surfaces.is_empty()
                && explicitly_uncovered.is_empty(),
            missing_surfaces,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        id: &str,
        parent: Option<&str>,
        kind: ReceiptEventKind,
        surface: ReceiptSurface,
    ) -> OperationReceiptEvent {
        OperationReceiptEvent {
            event_id: id.into(),
            operation_id: "op-1".into(),
            parent_event_id: parent.map(str::to_string),
            timestamp_ms: 1,
            kind,
            surface,
            actor: "agent:test".into(),
            references: Vec::new(),
            attributes: BTreeMap::new(),
        }
    }

    fn complete_receipt() -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "default".into(),
            operation_class: "model_inference".into(),
            initiating_actor: "agent:test".into(),
            schema_version: "schema-v1".into(),
            policy_version: "policy-v1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(5),
            events: vec![
                event(
                    "intent",
                    None,
                    ReceiptEventKind::IntentRecorded,
                    ReceiptSurface::Intent,
                ),
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    ReceiptSurface::Policy,
                ),
                event(
                    "route",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    ReceiptSurface::Routing,
                ),
                event(
                    "budget",
                    Some("route"),
                    ReceiptEventKind::BudgetDecided,
                    ReceiptSurface::Budget,
                ),
                event(
                    "outcome",
                    Some("budget"),
                    ReceiptEventKind::OutcomeRecorded,
                    ReceiptSurface::Outcome,
                ),
            ],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
        }
    }

    #[test]
    fn complete_receipt_is_order_independent() {
        let mut receipt = complete_receipt();
        receipt.events.reverse();
        assert_eq!(
            receipt.completeness(),
            ReceiptCompleteness {
                complete: true,
                missing_surfaces: Vec::new(),
                errors: Vec::new(),
            }
        );
    }

    #[test]
    fn missing_surface_keeps_receipt_partial() {
        let mut receipt = complete_receipt();
        receipt
            .events
            .retain(|event| event.surface != ReceiptSurface::Budget);
        receipt.uncovered_surfaces.push(UncoveredSurface {
            surface: ReceiptSurface::Budget,
            reason: "legacy caller did not report a budget decision".into(),
        });
        let result = receipt.completeness();
        assert!(!result.complete);
        assert_eq!(result.missing_surfaces, vec![ReceiptSurface::Budget]);
    }

    #[test]
    fn duplicate_event_is_rejected() {
        let mut receipt = complete_receipt();
        receipt.events.push(receipt.events[1].clone());
        let result = receipt.completeness();
        assert!(!result.complete);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("duplicate event id"))
        );
    }

    #[test]
    fn cross_operation_event_is_rejected() {
        let mut receipt = complete_receipt();
        receipt.events[2].operation_id = "op-2".into();
        let result = receipt.completeness();
        assert!(!result.complete);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("belongs to operation op-2"))
        );
    }

    #[test]
    fn mismatched_event_kind_and_surface_is_rejected() {
        let mut receipt = complete_receipt();
        receipt.events[1].surface = ReceiptSurface::Routing;
        receipt.events[2].surface = ReceiptSurface::Policy;
        let result = receipt.completeness();
        assert!(!result.complete);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("requires surface"))
        );
    }
}
