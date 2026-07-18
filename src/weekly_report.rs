//! Namespace-scoped weekly projections over authorized operation reports.

use crate::operation_report::{
    ExternalEvidenceVersion, OPERATION_REPORT_VERSION, OperationReport, OperationSummary,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const TEAM_WEEKLY_REPORT_VERSION: &str = "team.weekly-report/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamWeeklyReport {
    pub version: String,
    pub source_report_version: String,
    pub namespace: String,
    pub since_ms: i64,
    pub until_ms: i64,
    pub generated_at_ms: i64,
    pub summary: OperationSummary,
    pub principals: Vec<PrincipalSummary>,
    pub receipt_references: Vec<ReceiptReference>,
    pub attestation_references: Vec<EvidenceReference>,
    pub external_evidence_references: Vec<WeeklyExternalEvidence>,
    pub retention: RetentionSummary,
    pub unresolved_governance: Vec<UnresolvedGovernanceEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrincipalSummary {
    pub principal: String,
    pub summary: OperationSummary,
    pub receipt_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReceiptReference {
    pub operation_id: String,
    pub reference: String,
    pub source_receipt_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub operation_id: String,
    pub event_id: String,
    pub kind: String,
    pub reference: String,
    pub content_hash: Option<String>,
    pub disclosed_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WeeklyExternalEvidence {
    pub operation_id: String,
    #[serde(flatten)]
    pub evidence: ExternalEvidenceVersion,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionSummary {
    pub operations_with_redactions: usize,
    pub retention_redactions: usize,
    pub tombstone_redactions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnresolvedGovernanceEvent {
    pub operation_id: String,
    pub event_id: Option<String>,
    pub category: String,
    pub status: String,
    pub detail: String,
}

impl TeamWeeklyReport {
    pub fn from_reports(
        reports: &[OperationReport],
        namespace: &str,
        since_ms: i64,
        until_ms: i64,
        generated_at_ms: i64,
    ) -> Result<Self, String> {
        let namespace = namespace.trim();
        if namespace.is_empty() {
            return Err("namespace is required".into());
        }
        if since_ms >= until_ms {
            return Err("since_ms must be earlier than until_ms".into());
        }
        let mut selected_by_id = BTreeMap::<String, &OperationReport>::new();
        for report in reports.iter().filter(|report| {
            report.namespace == namespace
                && report.started_at_ms >= since_ms
                && report.started_at_ms < until_ms
        }) {
            if report.version != OPERATION_REPORT_VERSION
                || !report.governance.authorization_enforced_at_source
                || !report.governance.receipt_disclosures_only
            {
                return Err(format!(
                    "operation report {:?} is not an authorized disclosure-only projection",
                    report.operation_id
                ));
            }
            if let Some(existing) = selected_by_id.get(&report.operation_id)
                && *existing != report
            {
                return Err(format!(
                    "operation report {:?} has conflicting projections",
                    report.operation_id
                ));
            }
            selected_by_id.insert(report.operation_id.clone(), report);
        }
        let selected = selected_by_id.into_values().cloned().collect::<Vec<_>>();

        let mut by_principal = BTreeMap::<String, Vec<OperationReport>>::new();
        let mut receipt_references = BTreeSet::new();
        let mut attestation_references = BTreeSet::new();
        let mut external_evidence_references = BTreeSet::new();
        let mut unresolved_governance = BTreeSet::new();
        let mut retention = RetentionSummary::default();

        for report in &selected {
            by_principal
                .entry(report.initiating_actor.clone())
                .or_default()
                .push(report.clone());
            receipt_references.insert(ReceiptReference {
                operation_id: report.operation_id.clone(),
                reference: format!("receipt:{}", report.operation_id),
                source_receipt_version: report.source_receipt_version.clone(),
            });
            let operation_redactions =
                report.governance.retention_redactions + report.governance.tombstone_redactions;
            retention.operations_with_redactions += (operation_redactions > 0) as usize;
            retention.retention_redactions += report.governance.retention_redactions;
            retention.tombstone_redactions += report.governance.tombstone_redactions;

            for evidence in &report.external_evidence_versions {
                external_evidence_references.insert(WeeklyExternalEvidence {
                    operation_id: report.operation_id.clone(),
                    evidence: evidence.clone(),
                });
            }
            collect_event_references(
                report,
                &mut attestation_references,
                &mut unresolved_governance,
            );
            collect_report_gaps(report, &mut unresolved_governance);
        }

        let principals = by_principal
            .into_iter()
            .map(|(principal, reports)| PrincipalSummary {
                principal,
                summary: OperationSummary::from_reports(
                    &reports,
                    Some(namespace),
                    since_ms,
                    until_ms,
                ),
                receipt_references: reports
                    .iter()
                    .map(|report| format!("receipt:{}", report.operation_id))
                    .collect(),
            })
            .collect();

        Ok(Self {
            version: TEAM_WEEKLY_REPORT_VERSION.into(),
            source_report_version: OPERATION_REPORT_VERSION.into(),
            namespace: namespace.into(),
            since_ms,
            until_ms,
            generated_at_ms,
            summary: OperationSummary::from_reports(&selected, Some(namespace), since_ms, until_ms),
            principals,
            receipt_references: receipt_references.into_iter().collect(),
            attestation_references: attestation_references.into_iter().collect(),
            external_evidence_references: external_evidence_references.into_iter().collect(),
            retention,
            unresolved_governance: unresolved_governance.into_iter().collect(),
        })
    }
}

fn collect_event_references(
    report: &OperationReport,
    attestations: &mut BTreeSet<EvidenceReference>,
    unresolved: &mut BTreeSet<UnresolvedGovernanceEvent>,
) {
    for event in report.sections.values().flatten() {
        for reference in event.references.iter().filter(|reference| {
            !reference.omitted
                && (reference.kind == "attestation" || reference.kind.ends_with("_attestation"))
        }) {
            let mut disclosed_fields = reference.disclosed_fields.clone();
            disclosed_fields.sort();
            disclosed_fields.dedup();
            attestations.insert(EvidenceReference {
                operation_id: report.operation_id.clone(),
                event_id: event.event_id.clone(),
                kind: reference.kind.clone(),
                reference: reference.reference.clone(),
                content_hash: reference.content_hash.clone(),
                disclosed_fields,
            });
        }
    }
    collect_unresolved_governance_leaves(
        report,
        &["policy_decided"],
        "policy",
        &["blocked", "denied", "refused"],
        unresolved,
    );
    collect_unresolved_governance_leaves(
        report,
        &["approval_decided", "human_intervened"],
        "approval",
        &[
            "pending",
            "required",
            "requested",
            "parked",
            "waiting",
            "blocked",
            "denied",
            "rejected",
        ],
        unresolved,
    );
    collect_unresolved_failures(report, unresolved);
}

fn collect_unresolved_failures(
    report: &OperationReport,
    unresolved: &mut BTreeSet<UnresolvedGovernanceEvent>,
) {
    let events = report.sections.values().flatten().collect::<Vec<_>>();
    let by_id = events
        .iter()
        .map(|event| (event.event_id.as_str(), *event))
        .collect::<BTreeMap<_, _>>();
    for failure in events.iter().filter(|event| {
        event
            .attributes
            .get("status")
            .is_some_and(|status| matches!(status.as_str(), "failed" | "error"))
    }) {
        let resolved = events.iter().any(|candidate| {
            let successful = candidate.attributes.get("status").is_some_and(|status| {
                matches!(
                    status.as_str(),
                    "succeeded" | "success" | "ok" | "completed" | "resolved"
                )
            });
            successful
                && candidate.kind == failure.kind
                && is_descendant(candidate, &failure.event_id, &by_id)
        });
        if !resolved {
            insert_if_unresolved(report, failure, "failure", &["failed", "error"], unresolved);
        }
    }
}

fn is_descendant(
    candidate: &crate::operation_report::ReportEvent,
    ancestor_id: &str,
    by_id: &BTreeMap<&str, &crate::operation_report::ReportEvent>,
) -> bool {
    let mut parent = candidate.parent_event_id.as_deref();
    let mut remaining = by_id.len();
    while let Some(parent_id) = parent {
        if parent_id == ancestor_id {
            return true;
        }
        if remaining == 0 {
            return false;
        }
        remaining -= 1;
        parent = by_id
            .get(parent_id)
            .and_then(|event| event.parent_event_id.as_deref());
    }
    false
}

fn collect_unresolved_governance_leaves(
    report: &OperationReport,
    kinds: &[&str],
    category: &str,
    unresolved_statuses: &[&str],
    unresolved: &mut BTreeSet<UnresolvedGovernanceEvent>,
) {
    let events = report.sections.values().flatten().collect::<Vec<_>>();
    let by_id = events
        .iter()
        .map(|event| (event.event_id.as_str(), *event))
        .collect::<BTreeMap<_, _>>();
    for event in events
        .iter()
        .filter(|event| kinds.contains(&event.kind.as_str()))
    {
        let superseded = events.iter().any(|candidate| {
            let status = candidate
                .attributes
                .get("status")
                .or_else(|| candidate.attributes.get("decision"))
                .map(String::as_str)
                .unwrap_or_default();
            let transition = unresolved_statuses.contains(&status)
                || matches!(
                    status,
                    "allowed"
                        | "approved"
                        | "completed"
                        | "resolved"
                        | "succeeded"
                        | "success"
                        | "pass"
                        | "passed"
                );
            kinds.contains(&candidate.kind.as_str())
                && transition
                && is_descendant(candidate, &event.event_id, &by_id)
        });
        if !superseded {
            insert_if_unresolved(report, event, category, unresolved_statuses, unresolved);
        }
    }
}

fn insert_if_unresolved(
    report: &OperationReport,
    event: &crate::operation_report::ReportEvent,
    category: &str,
    unresolved_statuses: &[&str],
    unresolved: &mut BTreeSet<UnresolvedGovernanceEvent>,
) {
    let status = event
        .attributes
        .get("status")
        .or_else(|| event.attributes.get("decision"))
        .map(String::as_str)
        .unwrap_or_default();
    if unresolved_statuses.contains(&status) {
        unresolved.insert(UnresolvedGovernanceEvent {
            operation_id: report.operation_id.clone(),
            event_id: Some(event.event_id.clone()),
            category: category.into(),
            status: status.into(),
            detail: event
                .attributes
                .get("reason")
                .cloned()
                .unwrap_or_else(|| event.kind.clone()),
        });
    }
}

fn collect_report_gaps(
    report: &OperationReport,
    unresolved: &mut BTreeSet<UnresolvedGovernanceEvent>,
) {
    for surface in &report.missing_surfaces {
        unresolved.insert(UnresolvedGovernanceEvent {
            operation_id: report.operation_id.clone(),
            event_id: None,
            category: "missing_evidence".into(),
            status: "unresolved".into(),
            detail: surface.as_str().into(),
        });
    }
    for gap in &report.uncovered_surfaces {
        unresolved.insert(UnresolvedGovernanceEvent {
            operation_id: report.operation_id.clone(),
            event_id: None,
            category: "uncovered_evidence".into(),
            status: "unresolved".into(),
            detail: format!("{}: {}", gap.surface.as_str(), gap.reason),
        });
    }
    for error in &report.structural_errors {
        unresolved.insert(UnresolvedGovernanceEvent {
            operation_id: report.operation_id.clone(),
            event_id: None,
            category: "structural_error".into(),
            status: "error".into(),
            detail: error.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::GovernedReference;
    use crate::operation_report::{AssuranceClaims, ClaimState, GovernanceProjection};

    fn report(operation: &str, namespace: &str, actor: &str) -> OperationReport {
        OperationReport {
            version: OPERATION_REPORT_VERSION.into(),
            source_receipt_version: "operation.receipt/v1".into(),
            operation_id: operation.into(),
            parent_operation_id: None,
            namespace: namespace.into(),
            operation_class: "analysis".into(),
            initiating_actor: actor.into(),
            schema_version: "schema/v1".into(),
            policy_version: "policy/v1".into(),
            started_at_ms: 10,
            completed_at_ms: Some(20),
            duration_ms: Some(10),
            governance: GovernanceProjection {
                authorization_enforced_at_source: true,
                receipt_disclosures_only: true,
                retention_redactions: 1,
                tombstone_redactions: 0,
            },
            claims: AssuranceClaims {
                evidence_complete: true,
                integrity: ClaimState::Verified,
                policy_compliance: ClaimState::Verified,
            },
            external_evidence_versions: vec![ExternalEvidenceVersion {
                submission_id: format!("submission-{operation}"),
                source_version: "v2".into(),
                content_digest: "digest".into(),
                disclosed_fields: vec!["status".into()],
                receipt_event_id: "policy".into(),
            }],
            sections: BTreeMap::from([(
                "policy".into(),
                vec![crate::operation_report::ReportEvent {
                    event_id: "policy".into(),
                    parent_event_id: None,
                    timestamp_ms: 11,
                    kind: "policy_decided".into(),
                    actor: "policy".into(),
                    attributes: BTreeMap::from([
                        ("status".into(), "denied".into()),
                        ("cost_usd_micros".into(), "50".into()),
                    ]),
                    references: vec![GovernedReference {
                        kind: "policy_attestation".into(),
                        reference: format!("attestation:{operation}"),
                        content_hash: Some("hash".into()),
                        disclosed_fields: vec!["decision".into()],
                        omitted: false,
                        omission_reason: None,
                    }],
                }],
            )]),
            missing_surfaces: vec![],
            uncovered_surfaces: vec![],
            structural_errors: vec![],
        }
    }

    #[test]
    fn weekly_report_aggregates_principals_and_governed_evidence() {
        let weekly = TeamWeeklyReport::from_reports(
            &[
                report("op-a", "acme", "alice"),
                report("op-b", "acme", "bob"),
            ],
            "acme",
            0,
            100,
            100,
        )
        .unwrap();
        assert_eq!(weekly.summary.operation_count, 2);
        assert_eq!(weekly.summary.spend_usd_micros, 100);
        assert_eq!(weekly.principals.len(), 2);
        assert_eq!(weekly.attestation_references.len(), 2);
        assert_eq!(weekly.external_evidence_references.len(), 2);
        assert_eq!(weekly.retention.retention_redactions, 2);
        assert_eq!(weekly.unresolved_governance.len(), 2);
    }

    #[test]
    fn weekly_report_never_projects_another_namespace() {
        let mut foreign = report("foreign-secret", "beta", "mallory");
        foreign.sections.get_mut("policy").unwrap()[0]
            .attributes
            .insert("reason".into(), "classified beta reason".into());
        let weekly = TeamWeeklyReport::from_reports(
            &[report("visible", "acme", "alice"), foreign],
            "acme",
            0,
            100,
            100,
        )
        .unwrap();
        let json = serde_json::to_string(&weekly).unwrap();
        assert_eq!(weekly.summary.operation_count, 1);
        assert!(!json.contains("foreign-secret"));
        assert!(!json.contains("mallory"));
        assert!(!json.contains("classified beta reason"));
    }

    #[test]
    fn weekly_report_validates_scope_and_window() {
        assert!(TeamWeeklyReport::from_reports(&[], " ", 0, 1, 1).is_err());
        assert!(TeamWeeklyReport::from_reports(&[], "acme", 1, 1, 1).is_err());
    }

    #[test]
    fn weekly_report_requires_authorized_inputs_and_deduplicates_retries() {
        let authorized = report("op-a", "acme", "alice");
        let weekly = TeamWeeklyReport::from_reports(
            &[authorized.clone(), authorized.clone()],
            "acme",
            0,
            100,
            100,
        )
        .unwrap();
        assert_eq!(weekly.summary.operation_count, 1);

        let mut unauthorized = authorized.clone();
        unauthorized.governance.authorization_enforced_at_source = false;
        assert!(TeamWeeklyReport::from_reports(&[unauthorized], "acme", 0, 100, 100).is_err());

        let mut conflicting = authorized.clone();
        conflicting.policy_version = "different".into();
        assert!(
            TeamWeeklyReport::from_reports(&[authorized, conflicting], "acme", 0, 100, 100,)
                .is_err()
        );
    }

    #[test]
    fn later_governance_decisions_clear_historical_failures() {
        let mut recovered = report("op-a", "acme", "alice");
        recovered
            .sections
            .get_mut("policy")
            .unwrap()
            .push(crate::operation_report::ReportEvent {
                event_id: "aaa-policy-recovered".into(),
                parent_event_id: Some("policy".into()),
                timestamp_ms: 11,
                kind: "policy_decided".into(),
                actor: "policy".into(),
                attributes: BTreeMap::from([("status".into(), "allowed".into())]),
                references: vec![],
            });
        let weekly = TeamWeeklyReport::from_reports(&[recovered], "acme", 0, 100, 100).unwrap();
        assert!(weekly.unresolved_governance.is_empty());
    }

    #[test]
    fn approval_branches_preserve_each_unresolved_leaf_status() {
        let mut operation = report("op-a", "acme", "alice");
        let events = operation.sections.get_mut("policy").unwrap();
        events[0]
            .attributes
            .insert("status".into(), "allowed".into());
        for (event_id, parent_event_id, status, timestamp_ms) in [
            ("approval-resolved", "policy", "pending", 12),
            (
                "approval-resolved-result",
                "approval-resolved",
                "approved",
                13,
            ),
            ("approval-waiting", "policy", "waiting", 14),
            ("approval-parked", "policy", "parked", 15),
        ] {
            events.push(crate::operation_report::ReportEvent {
                event_id: event_id.into(),
                parent_event_id: Some(parent_event_id.into()),
                timestamp_ms,
                kind: "approval_decided".into(),
                actor: "approver".into(),
                attributes: BTreeMap::from([("status".into(), status.into())]),
                references: vec![],
            });
        }
        events
            .iter_mut()
            .find(|event| event.event_id == "approval-resolved-result")
            .unwrap()
            .kind = "human_intervened".into();
        events
            .iter_mut()
            .find(|event| event.event_id == "approval-waiting")
            .unwrap()
            .kind = "human_intervened".into();
        events.push(crate::operation_report::ReportEvent {
            event_id: "approval-comment".into(),
            parent_event_id: Some("approval-waiting".into()),
            timestamp_ms: 16,
            kind: "human_intervened".into(),
            actor: "approver".into(),
            attributes: BTreeMap::from([("status".into(), "commented".into())]),
            references: vec![],
        });

        let weekly = TeamWeeklyReport::from_reports(&[operation], "acme", 0, 100, 100).unwrap();
        let unresolved_ids = weekly
            .unresolved_governance
            .iter()
            .filter_map(|event| event.event_id.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            unresolved_ids,
            BTreeSet::from(["approval-parked", "approval-waiting"])
        );
    }

    #[test]
    fn failed_events_remain_unresolved_until_a_later_recovery() {
        let mut failed = report("op-a", "acme", "alice");
        let events = failed.sections.get_mut("policy").unwrap();
        events[0]
            .attributes
            .insert("status".into(), "allowed".into());
        events.push(crate::operation_report::ReportEvent {
            event_id: "call-failed".into(),
            parent_event_id: Some("policy".into()),
            timestamp_ms: 12,
            kind: "model_called".into(),
            actor: "gateway".into(),
            attributes: BTreeMap::from([("status".into(), "failed".into())]),
            references: vec![],
        });
        let weekly =
            TeamWeeklyReport::from_reports(&[failed.clone()], "acme", 0, 100, 100).unwrap();
        assert_eq!(weekly.unresolved_governance.len(), 1);
        assert_eq!(weekly.unresolved_governance[0].category, "failure");

        failed
            .sections
            .get_mut("policy")
            .unwrap()
            .push(crate::operation_report::ReportEvent {
                event_id: "unrelated-outcome".into(),
                parent_event_id: Some("policy".into()),
                timestamp_ms: 13,
                kind: "outcome_recorded".into(),
                actor: "gateway".into(),
                attributes: BTreeMap::from([("status".into(), "success".into())]),
                references: vec![],
            });
        let still_failed =
            TeamWeeklyReport::from_reports(&[failed.clone()], "acme", 0, 100, 100).unwrap();
        assert_eq!(still_failed.unresolved_governance.len(), 1);

        failed
            .sections
            .get_mut("policy")
            .unwrap()
            .push(crate::operation_report::ReportEvent {
                event_id: "call-recovered".into(),
                parent_event_id: Some("call-failed".into()),
                timestamp_ms: 12,
                kind: "model_called".into(),
                actor: "gateway".into(),
                attributes: BTreeMap::from([("status".into(), "completed".into())]),
                references: vec![],
            });
        let recovered = TeamWeeklyReport::from_reports(&[failed], "acme", 0, 100, 100).unwrap();
        assert!(recovered.unresolved_governance.is_empty());
    }
}
