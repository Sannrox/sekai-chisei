//! Human-readable projections of canonical governed-operation receipts.

use crate::chisei::receipt::{
    GovernedReference, OperationReceipt, OperationReceiptEvent, ReceiptSurface, UncoveredSurface,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPERATION_REPORT_VERSION: &str = "operation.report/v1";
pub const OPERATION_SUMMARY_VERSION: &str = "operation.summary/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationSummary {
    pub version: String,
    pub namespace: Option<String>,
    pub since_ms: i64,
    pub until_ms: i64,
    pub operation_count: usize,
    pub spend_usd_micros: i64,
    pub budget_pressure_events: usize,
    pub policy_blocks: usize,
    pub failure_events: usize,
    pub degraded_mode_events: usize,
    pub expensive_operations: Vec<ExpensiveOperation>,
    pub mean_outcome_quality: Option<f64>,
    pub complete_evidence_operations: usize,
    pub evidence_coverage_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpensiveOperation {
    pub operation_id: String,
    pub cost_usd_micros: i64,
}

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
    #[serde(default)]
    pub governance: GovernanceProjection,
    pub claims: AssuranceClaims,
    #[serde(default)]
    pub external_evidence_versions: Vec<ExternalEvidenceVersion>,
    pub sections: BTreeMap<String, Vec<ReportEvent>>,
    pub missing_surfaces: Vec<ReceiptSurface>,
    pub uncovered_surfaces: Vec<UncoveredSurface>,
    pub structural_errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExternalEvidenceVersion {
    pub submission_id: String,
    pub source_version: String,
    pub content_digest: String,
    pub disclosed_fields: Vec<String>,
    pub receipt_event_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProjection {
    pub authorization_enforced_at_source: bool,
    pub receipt_disclosures_only: bool,
    pub retention_redactions: usize,
    pub tombstone_redactions: usize,
}

impl OperationReport {
    pub fn from_receipt(receipt: &OperationReceipt) -> Self {
        Self::project(receipt, false)
    }

    pub fn from_authorized_receipt(receipt: &OperationReceipt) -> Self {
        Self::project(receipt, true)
    }

    fn project(receipt: &OperationReceipt, authorization_enforced_at_source: bool) -> Self {
        let completeness = receipt.completeness();
        let mut sections = BTreeMap::<String, Vec<ReportEvent>>::new();
        let mut retention_redactions = 0usize;
        let mut tombstone_redactions = 0usize;
        let mut external_evidence_versions = Vec::new();
        let mut evidence_projection_errors = Vec::new();
        for event in causally_ordered_events(receipt) {
            let projected = project_event(event);
            for reference in projected
                .references
                .iter()
                .filter(|reference| reference.omitted)
            {
                let reason = reference.omission_reason.as_deref().unwrap_or_default();
                retention_redactions += reason.contains("retention") as usize;
                tombstone_redactions += reason.contains("tombstone") as usize;
            }
            for reference in projected
                .references
                .iter()
                .filter(|reference| reference.kind == "external_evidence" && !reference.omitted)
            {
                match external_evidence_version(&projected.event_id, reference) {
                    Ok(version) => external_evidence_versions.push(version),
                    Err(error) => evidence_projection_errors.push(error),
                }
            }
            sections
                .entry(event.surface.as_str().into())
                .or_default()
                .push(projected);
        }
        let duration_ms = receipt
            .completed_at_ms
            .map(|end| end.saturating_sub(receipt.started_at_ms));
        let mut structural_errors = completeness.errors;
        if duration_ms.is_some_and(|duration| duration < 0) {
            structural_errors.push("completed_at_ms precedes started_at_ms".into());
        }
        external_evidence_versions.sort_by(|left, right| {
            (
                &left.submission_id,
                &left.source_version,
                &left.receipt_event_id,
            )
                .cmp(&(
                    &right.submission_id,
                    &right.source_version,
                    &right.receipt_event_id,
                ))
        });
        external_evidence_versions.dedup();
        structural_errors.extend(evidence_projection_errors);
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
            governance: GovernanceProjection {
                authorization_enforced_at_source,
                receipt_disclosures_only: true,
                retention_redactions,
                tombstone_redactions,
            },
            claims: AssuranceClaims {
                evidence_complete: completeness.complete && structural_errors.is_empty(),
                integrity: ClaimState::NotVerified,
                policy_compliance: ClaimState::NotVerified,
            },
            external_evidence_versions,
            sections,
            missing_surfaces: completeness.missing_surfaces,
            uncovered_surfaces: receipt.uncovered_surfaces.clone(),
            structural_errors,
        }
    }
}

fn external_evidence_version(
    event_id: &str,
    reference: &GovernedReference,
) -> Result<ExternalEvidenceVersion, String> {
    let value = reference
        .reference
        .strip_prefix("evidence:")
        .ok_or_else(|| {
            format!(
                "external evidence reference {} has no evidence prefix",
                reference.reference
            )
        })?;
    let (submission_id, source_version) = value
        .split_once('@')
        .filter(|(submission_id, source_version)| {
            !submission_id.trim().is_empty() && !source_version.trim().is_empty()
        })
        .ok_or_else(|| {
            format!(
                "external evidence reference {} does not pin a source version",
                reference.reference
            )
        })?;
    let content_digest = reference
        .content_hash
        .as_deref()
        .filter(|digest| !digest.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "external evidence reference {} does not pin a content digest",
                reference.reference
            )
        })?;
    let mut disclosed_fields = reference.disclosed_fields.clone();
    disclosed_fields.sort();
    disclosed_fields.dedup();
    Ok(ExternalEvidenceVersion {
        submission_id: submission_id.into(),
        source_version: source_version.into(),
        content_digest: content_digest.into(),
        disclosed_fields,
        receipt_event_id: event_id.into(),
    })
}

fn project_event(event: &OperationReceiptEvent) -> ReportEvent {
    ReportEvent {
        event_id: event.event_id.clone(),
        parent_event_id: event.parent_event_id.clone(),
        timestamp_ms: event.timestamp_ms,
        kind: event.kind.as_str().into(),
        actor: event.actor.clone(),
        attributes: event.attributes.clone(),
        references: event.references.clone(),
    }
}

impl OperationSummary {
    pub fn from_reports(
        reports: &[OperationReport],
        namespace: Option<&str>,
        since_ms: i64,
        until_ms: i64,
    ) -> Self {
        let selected = reports
            .iter()
            .filter(|report| {
                report.started_at_ms >= since_ms
                    && report.started_at_ms < until_ms
                    && namespace.is_none_or(|value| report.namespace == value)
            })
            .collect::<Vec<_>>();
        let mut spend = 0i64;
        let mut budget_pressure = 0usize;
        let mut policy_blocks = 0usize;
        let mut failures = 0usize;
        let mut degraded = 0usize;
        let mut quality = Vec::new();
        let mut expensive_operations = Vec::new();
        for report in &selected {
            let mut operation_cost = 0i64;
            for event in report.sections.values().flatten() {
                operation_cost = operation_cost
                    .saturating_add(attribute_i64(event, "cost_usd_micros").unwrap_or(0));
                budget_pressure += attribute_true(event, "budget_pressure") as usize;
                policy_blocks += (event.kind == "policy_decided"
                    && ["decision", "status"].iter().any(|key| {
                        matches!(
                            event.attributes.get(*key).map(String::as_str),
                            Some("blocked" | "denied" | "refused")
                        )
                    })) as usize;
                failures += matches!(
                    event.attributes.get("status").map(String::as_str),
                    Some("failed" | "error")
                ) as usize;
                degraded += attribute_true(event, "degraded_mode") as usize;
                if event.kind == "outcome_recorded"
                    && let Some(value) = attribute_f64(event, "quality_score")
                {
                    quality.push(value);
                }
            }
            spend = spend.saturating_add(operation_cost);
            expensive_operations.push(ExpensiveOperation {
                operation_id: report.operation_id.clone(),
                cost_usd_micros: operation_cost,
            });
        }
        expensive_operations.sort_by_key(|item| std::cmp::Reverse(item.cost_usd_micros));
        expensive_operations.truncate(10);
        let complete = selected
            .iter()
            .filter(|report| report.claims.evidence_complete)
            .count();
        let count = selected.len();
        Self {
            version: OPERATION_SUMMARY_VERSION.into(),
            namespace: namespace.map(str::to_string),
            since_ms,
            until_ms,
            operation_count: count,
            spend_usd_micros: spend,
            budget_pressure_events: budget_pressure,
            policy_blocks,
            failure_events: failures,
            degraded_mode_events: degraded,
            expensive_operations,
            mean_outcome_quality: (!quality.is_empty())
                .then(|| quality.iter().sum::<f64>() / quality.len() as f64),
            complete_evidence_operations: complete,
            evidence_coverage_ratio: if count == 0 {
                0.0
            } else {
                complete as f64 / count as f64
            },
        }
    }
}

fn attribute_i64(event: &ReportEvent, key: &str) -> Option<i64> {
    event.attributes.get(key)?.parse().ok()
}
fn attribute_f64(event: &ReportEvent, key: &str) -> Option<f64> {
    event.attributes.get(key)?.parse().ok()
}
fn attribute_true(event: &ReportEvent, key: &str) -> bool {
    event
        .attributes
        .get(key)
        .is_some_and(|value| value == "true")
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

    #[test]
    fn summary_filters_namespace_and_reports_cost_quality_and_coverage() {
        let mut first = OperationReport::from_receipt(&receipt());
        let outcome = first
            .sections
            .get_mut("outcome")
            .unwrap()
            .first_mut()
            .unwrap();
        outcome
            .attributes
            .insert("cost_usd_micros".into(), "1200".into());
        outcome
            .attributes
            .insert("quality_score".into(), "0.8".into());
        first
            .sections
            .entry("policy".into())
            .or_default()
            .push(ReportEvent {
                event_id: "policy".into(),
                parent_event_id: Some("intent".into()),
                timestamp_ms: 1,
                kind: "policy_decided".into(),
                actor: "policy".into(),
                attributes: BTreeMap::from([("status".into(), "denied".into())]),
                references: vec![],
            });
        let mut second = first.clone();
        second.operation_id = "op-2".into();
        second.namespace = "other".into();
        let summary = OperationSummary::from_reports(&[first, second], Some("team-a"), 0, 100);
        assert_eq!(summary.operation_count, 1);
        assert_eq!(summary.spend_usd_micros, 1200);
        assert_eq!(summary.mean_outcome_quality, Some(0.8));
        assert_eq!(summary.policy_blocks, 1);
        assert_eq!(summary.evidence_coverage_ratio, 0.0);
    }

    #[test]
    fn canonical_retention_omissions_are_preserved_without_self_redaction() {
        let mut source = receipt();
        let outcome = source
            .events
            .iter_mut()
            .find(|event| event.event_id == "outcome")
            .unwrap();
        outcome.references.push(GovernedReference {
            kind: "artifact".into(),
            reference: "artifact-1".into(),
            content_hash: None,
            disclosed_fields: vec![],
            omitted: true,
            omission_reason: Some("retention period elapsed".into()),
        });
        let report = OperationReport::from_authorized_receipt(&source);
        let projected = &report.sections["outcome"][0];
        assert!(projected.references[0].omitted);
        assert!(projected.references[0].disclosed_fields.is_empty());
        assert_eq!(report.governance.retention_redactions, 1);
        assert!(report.governance.authorization_enforced_at_source);
    }

    #[test]
    fn legacy_v1_reports_deserialize_without_stronger_governance_claims() {
        let report = OperationReport::from_receipt(&receipt());
        let mut json = serde_json::to_value(report).unwrap();
        json.as_object_mut().unwrap().remove("governance");
        let restored: OperationReport = serde_json::from_value(json).unwrap();
        assert_eq!(restored.governance, GovernanceProjection::default());
        assert!(restored.external_evidence_versions.is_empty());
    }

    #[test]
    fn report_projects_exact_external_evidence_versions() {
        let mut source = receipt();
        let intent = source
            .events
            .iter_mut()
            .find(|event| event.event_id == "intent")
            .unwrap();
        intent.references.push(GovernedReference {
            kind: "external_evidence".into(),
            reference: "evidence:submission-7@attempt-2".into(),
            content_hash: Some("abc123".into()),
            disclosed_fields: vec!["status".into(), "status".into(), "outcome".into()],
            omitted: false,
            omission_reason: None,
        });
        let report = OperationReport::from_authorized_receipt(&source);
        assert_eq!(
            report.external_evidence_versions,
            vec![ExternalEvidenceVersion {
                submission_id: "submission-7".into(),
                source_version: "attempt-2".into(),
                content_digest: "abc123".into(),
                disclosed_fields: vec!["outcome".into(), "status".into()],
                receipt_event_id: "intent".into(),
            }]
        );
    }

    #[test]
    fn malformed_external_evidence_reference_prevents_completeness_claim() {
        let mut source = receipt();
        source.events[0].references.push(GovernedReference {
            kind: "external_evidence".into(),
            reference: "evidence:submission-without-version".into(),
            content_hash: Some("abc123".into()),
            disclosed_fields: vec![],
            omitted: false,
            omission_reason: None,
        });
        let report = OperationReport::from_receipt(&source);
        assert!(!report.claims.evidence_complete);
        assert!(
            report
                .structural_errors
                .iter()
                .any(|error| error.contains("does not pin a source version"))
        );
    }
}
