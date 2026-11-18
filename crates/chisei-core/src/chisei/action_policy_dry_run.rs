//! Historical dry-run of a candidate Action policy (#2121).
//!
//! Replays the action-policy decisions recorded on governed action instance
//! admission receipts (#3016) against a **candidate** `ActionPolicy` for one
//! scope. The candidate replaces only that scope's policy: a submit decided
//! by a more specific scope stays as it was. Pure: no I/O, no instance is
//! parked, resumed or written, and the candidate is never stored.

use crate::chisei::policy_dry_run::{MAX_DRY_RUN_RECEIPTS, MAX_DRY_RUN_SAMPLES, receipt_in_window};
use crate::chisei::receipt::{OperationReceipt, ReceiptEventKind};
use sekai_types::action_policy::{ActionDecision, ActionPolicy};
use sekai_types::risk_class::RiskClass;
use serde::Serialize;
use std::collections::BTreeMap;

/// `operation_class` of a governed action instance admission receipt.
const ACTION_INSTANCE_OPERATION_CLASS: &str = "governed_action_instance";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActionDryRunDelta {
    Unchanged,
    WouldDeny,
    WouldAllow,
    WouldRequireApproval,
    WouldSkipApproval,
    InsufficientHistory,
}

impl ActionDryRunDelta {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::WouldDeny => "would_deny",
            Self::WouldAllow => "would_allow",
            Self::WouldRequireApproval => "would_require_approval",
            Self::WouldSkipApproval => "would_skip_approval",
            Self::InsufficientHistory => "insufficient_history",
        }
    }
}

/// One past submit the candidate would decide differently, or could not
/// replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionDryRunSample {
    pub operation_id: String,
    /// The original action instance, so the sample links to its decision.
    pub instance_id: String,
    pub historical_decision: String,
    /// `action_policy_version` of the policy that decided the submit.
    pub historical_policy_version: String,
    pub candidate_decision: String,
    /// Candidate clause: `action_override:<a>`, `risk_override:<r>`, or
    /// `default_decision`. Empty for `insufficient_history`.
    pub candidate_rule: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ActionDryRunCounts {
    pub evaluated: u32,
    pub unchanged: u32,
    pub would_deny: u32,
    pub would_allow: u32,
    pub would_require_approval: u32,
    pub would_skip_approval: u32,
    pub insufficient_history: u32,
}

impl ActionDryRunCounts {
    fn add(&mut self, delta: ActionDryRunDelta) {
        self.evaluated += 1;
        let slot = match delta {
            ActionDryRunDelta::Unchanged => &mut self.unchanged,
            ActionDryRunDelta::WouldDeny => &mut self.would_deny,
            ActionDryRunDelta::WouldAllow => &mut self.would_allow,
            ActionDryRunDelta::WouldRequireApproval => &mut self.would_require_approval,
            ActionDryRunDelta::WouldSkipApproval => &mut self.would_skip_approval,
            ActionDryRunDelta::InsufficientHistory => &mut self.insufficient_history,
        };
        *slot += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionPolicyDryRunReport {
    pub namespace: String,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub candidate_scope: String,
    /// `ActionPolicy::version` of the candidate.
    pub candidate_policy_version: String,
    pub counts: ActionDryRunCounts,
    /// At most `MAX_DRY_RUN_SAMPLES` per class; `unchanged` has none.
    pub samples: BTreeMap<ActionDryRunDelta, Vec<ActionDryRunSample>>,
}

/// Dry-run `candidate` over the admission receipts of `namespace` that fall
/// in the window. Receipts of other operation classes are skipped.
pub fn dry_run_action_policy_over_receipts(
    namespace: &str,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
    candidate: &ActionPolicy,
    receipts: &[OperationReceipt],
) -> Result<ActionPolicyDryRunReport, String> {
    if namespace.trim().is_empty() {
        return Err("namespace required".into());
    }
    if candidate.scope.trim().is_empty() {
        return Err("candidate scope required".into());
    }
    if end_timestamp_ms <= start_timestamp_ms {
        return Err("end_timestamp_ms must be greater than start_timestamp_ms".into());
    }
    if receipts.len() > MAX_DRY_RUN_RECEIPTS {
        return Err(format!(
            "policy dry-run receipt limit exceeded ({MAX_DRY_RUN_RECEIPTS})"
        ));
    }
    let mut counts = ActionDryRunCounts::default();
    let mut samples: BTreeMap<ActionDryRunDelta, Vec<ActionDryRunSample>> = BTreeMap::new();
    for receipt in receipts.iter().filter(|receipt| {
        receipt.namespace == namespace
            && receipt.operation_class == ACTION_INSTANCE_OPERATION_CLASS
            && receipt_in_window(receipt, start_timestamp_ms, end_timestamp_ms)
    }) {
        let (delta, sample) = replay(receipt, candidate);
        counts.add(delta);
        if delta != ActionDryRunDelta::Unchanged {
            let class = samples.entry(delta).or_default();
            if class.len() < MAX_DRY_RUN_SAMPLES {
                class.push(sample);
            }
        }
    }
    Ok(ActionPolicyDryRunReport {
        namespace: namespace.into(),
        start_timestamp_ms,
        end_timestamp_ms,
        candidate_scope: candidate.scope.clone(),
        candidate_policy_version: candidate.version(),
        counts,
        samples,
    })
}

/// Whether the candidate's scope would have decided a past submit.
enum Reach {
    Decides,
    /// A more specific scope decided it, or the candidate does not apply.
    NotReached,
    /// Depends on the Action type's policy scope, which receipts do not record.
    Unknown,
}

/// Scope resolution is agent, then `project:<p>`, then the namespace
/// (`candidate_scopes`). `recorded` is the scope that decided the submit,
/// empty when none resolved.
fn reach(candidate: &str, recorded: &str, actor: &str, namespace: &str) -> Reach {
    if candidate == recorded || candidate == format!("agent:{actor}") {
        return Reach::Decides;
    }
    if recorded.starts_with("agent:") {
        return Reach::NotReached;
    }
    if candidate == namespace {
        // The last scope: it decides only when nothing more specific did.
        return if recorded.is_empty() {
            Reach::Decides
        } else {
            Reach::NotReached
        };
    }
    if candidate.starts_with("project:") {
        // A recorded project scope is the type's project; another project
        // candidate never applies to it.
        return if recorded.starts_with("project:") {
            Reach::NotReached
        } else {
            Reach::Unknown
        };
    }
    Reach::NotReached
}

fn replay(
    receipt: &OperationReceipt,
    candidate: &ActionPolicy,
) -> (ActionDryRunDelta, ActionDryRunSample) {
    let instance_id = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .and_then(|event| event.attributes.get("instance_id").cloned())
        .unwrap_or_default();
    let recorded = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::PolicyDecided)
        .map(|event| &event.attributes);
    let attribute = |key: &str| {
        recorded
            .and_then(|attributes| attributes.get(key))
            .cloned()
            .unwrap_or_default()
    };
    let historical_decision = attribute("action_policy_decision");
    let mut sample = ActionDryRunSample {
        operation_id: receipt.operation_id.clone(),
        instance_id,
        historical_decision: historical_decision.clone(),
        historical_policy_version: attribute("action_policy_version"),
        candidate_decision: String::new(),
        candidate_rule: String::new(),
        detail: String::new(),
    };
    let insufficient = |mut sample: ActionDryRunSample, detail: &str| {
        sample.detail = detail.into();
        (ActionDryRunDelta::InsufficientHistory, sample)
    };
    let action = attribute("action");
    let risk = RiskClass::parse(&attribute("risk_class"));
    // No policy resolved is the historical allow.
    let historical = match historical_decision.as_str() {
        "none" => Some(ActionDecision::Allow),
        other => ActionDecision::parse(other),
    };
    let (Some(historical), Some(risk), false) = (historical, risk, action.is_empty()) else {
        return insufficient(
            sample,
            "receipt lacks the action policy decision, action or risk class",
        );
    };
    let (candidate_decision, rule) = match reach(
        &candidate.scope,
        &attribute("action_policy_scope"),
        &receipt.initiating_actor,
        &receipt.namespace,
    ) {
        Reach::Decides => {
            let (decision, rule) = candidate.decide_with_rule(&action, risk);
            (decision, rule.to_string())
        }
        Reach::NotReached => {
            sample.detail = "decided by a scope the candidate does not replace".into();
            return (ActionDryRunDelta::Unchanged, sample);
        }
        Reach::Unknown => {
            return insufficient(
                sample,
                "whether the candidate scope applies depends on the Action type's policy scope",
            );
        }
    };
    sample.candidate_decision = candidate_decision.as_str().into();
    sample.candidate_rule = rule;
    let delta = match (historical, candidate_decision) {
        (before, after) if before == after => ActionDryRunDelta::Unchanged,
        (_, ActionDecision::Deny) => ActionDryRunDelta::WouldDeny,
        (_, ActionDecision::RequireApproval) => ActionDryRunDelta::WouldRequireApproval,
        (ActionDecision::RequireApproval, ActionDecision::Allow) => {
            ActionDryRunDelta::WouldSkipApproval
        }
        (_, ActionDecision::Allow) => ActionDryRunDelta::WouldAllow,
    };
    (delta, sample)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptSurface,
    };

    /// An admission receipt as #3016 records it; `policy` is
    /// `(decision, scope, version)`, `None` for a receipt written before.
    fn receipt(id: &str, actor: &str, policy: Option<(&str, &str, &str)>) -> OperationReceipt {
        let event =
            |kind: ReceiptEventKind, attributes: BTreeMap<String, String>| OperationReceiptEvent {
                event_id: format!("{id}:{kind:?}"),
                operation_id: id.into(),
                parent_event_id: None,
                timestamp_ms: 150,
                kind,
                surface: ReceiptSurface::Policy,
                actor: actor.into(),
                references: Vec::new(),
                attributes,
            };
        let mut policy_attributes = BTreeMap::from([
            ("decision".into(), "auto_apply".into()),
            ("action".into(), "submit_action_instance".into()),
        ]);
        if let Some((decision, scope, version)) = policy {
            policy_attributes.extend([
                ("action_policy_decision".into(), decision.into()),
                ("action_policy_scope".into(), scope.into()),
                ("action_policy_version".into(), version.into()),
                ("risk_class".into(), "write".into()),
            ]);
        }
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: id.into(),
            parent_operation_id: None,
            namespace: "acme".into(),
            operation_class: ACTION_INSTANCE_OPERATION_CLASS.into(),
            initiating_actor: actor.into(),
            schema_version: "action-instance/v1".into(),
            policy_version: "acme".into(),
            started_at_ms: 150,
            completed_at_ms: Some(150),
            events: vec![
                event(
                    ReceiptEventKind::IntentRecorded,
                    BTreeMap::from([("instance_id".into(), format!("gai-{id}"))]),
                ),
                event(ReceiptEventKind::PolicyDecided, policy_attributes),
            ],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        }
    }

    fn run(candidate: &ActionPolicy, receipts: &[OperationReceipt]) -> ActionPolicyDryRunReport {
        dry_run_action_policy_over_receipts("acme", 100, 200, candidate, receipts).unwrap()
    }

    fn ids(report: &ActionPolicyDryRunReport, delta: ActionDryRunDelta) -> Vec<&str> {
        report.samples.get(&delta).map_or(Vec::new(), |samples| {
            samples
                .iter()
                .map(|sample| sample.operation_id.as_str())
                .collect()
        })
    }

    #[test]
    fn flipping_a_risk_override_reports_only_the_submits_it_decides() {
        let current = ActionPolicy::allow_all("acme");
        let receipts = [
            receipt("op-1", "alice", Some(("allow", "acme", "v1"))),
            receipt("op-2", "bob", Some(("allow", "acme", "v1"))),
            // Decided by carol's own policy, which the candidate does not replace.
            receipt("op-3", "carol", Some(("allow", "agent:carol", "v9"))),
        ];
        let mut candidate = current.clone();
        candidate
            .risk_overrides
            .insert(RiskClass::Write, ActionDecision::RequireApproval);
        let report = run(&candidate, &receipts);
        assert_eq!(report.counts.evaluated, 3);
        assert_eq!(report.counts.would_require_approval, 2);
        assert_eq!(report.counts.unchanged, 1);
        assert_eq!(
            ids(&report, ActionDryRunDelta::WouldRequireApproval),
            ["op-1", "op-2"]
        );
        let sample = &report.samples[&ActionDryRunDelta::WouldRequireApproval][0];
        assert_eq!(sample.instance_id, "gai-op-1");
        assert_eq!(sample.historical_policy_version, "v1");
        assert_eq!(sample.candidate_rule, "risk_override:write");
        assert_eq!(report.candidate_policy_version, candidate.version());

        // The current policy itself changes nothing.
        let report = run(&current, &receipts);
        assert_eq!(report.counts.unchanged, 3);
        assert!(report.samples.is_empty());
    }

    #[test]
    fn delta_classes_follow_the_historical_and_candidate_decisions() {
        let receipts = [
            receipt("op-allow", "a", Some(("allow", "acme", "v1"))),
            receipt("op-parked", "a", Some(("require_approval", "acme", "v1"))),
            receipt("op-denied", "a", Some(("deny", "acme", "v1"))),
            // No policy resolved: the historical allow.
            receipt("op-none", "a", Some(("none", "", ""))),
        ];
        let mut deny = ActionPolicy::allow_all("acme");
        deny.default_decision = ActionDecision::Deny;
        let report = run(&deny, &receipts);
        assert_eq!(
            ids(&report, ActionDryRunDelta::WouldDeny),
            ["op-allow", "op-parked", "op-none"]
        );
        assert_eq!(report.counts.unchanged, 1);

        let allow = ActionPolicy::allow_all("acme");
        let report = run(&allow, &receipts);
        assert_eq!(
            ids(&report, ActionDryRunDelta::WouldSkipApproval),
            ["op-parked"]
        );
        assert_eq!(ids(&report, ActionDryRunDelta::WouldAllow), ["op-denied"]);
        assert_eq!(report.counts.unchanged, 2);
    }

    #[test]
    fn a_receipt_without_the_policy_record_is_insufficient_history() {
        let mut legacy = receipt("op-legacy", "a", None);
        let report = run(&ActionPolicy::allow_all("acme"), &[legacy.clone()]);
        assert_eq!(report.counts.insufficient_history, 1);
        assert_eq!(report.counts.unchanged, 0);

        // A missing risk class is never read as unchanged either.
        legacy = receipt("op-no-risk", "a", Some(("allow", "acme", "v1")));
        legacy.events[1].attributes.remove("risk_class");
        let report = run(&ActionPolicy::allow_all("acme"), &[legacy]);
        assert_eq!(
            ids(&report, ActionDryRunDelta::InsufficientHistory),
            ["op-no-risk"]
        );
    }

    #[test]
    fn candidate_scope_replaces_only_what_it_would_have_decided() {
        let deny = |scope: &str| {
            let mut policy = ActionPolicy::allow_all(scope);
            policy.default_decision = ActionDecision::Deny;
            policy
        };
        let receipts = [
            receipt("op-ns", "alice", Some(("allow", "acme", "v1"))),
            receipt("op-none", "alice", Some(("none", "", ""))),
            receipt("op-bob", "bob", Some(("allow", "acme", "v1"))),
        ];
        // A new agent policy takes over everything that actor submitted.
        let report = run(&deny("agent:alice"), &receipts);
        assert_eq!(
            ids(&report, ActionDryRunDelta::WouldDeny),
            ["op-ns", "op-none"]
        );
        // The namespace scope decides only where nothing more specific did.
        let report = run(&deny("acme"), &receipts);
        assert_eq!(
            ids(&report, ActionDryRunDelta::WouldDeny),
            ["op-ns", "op-none", "op-bob"]
        );
        // A project scope's reach depends on the type, which is not recorded.
        let report = run(&deny("project:acme"), &receipts);
        assert_eq!(report.counts.insufficient_history, 3);
    }

    #[test]
    fn only_action_admissions_in_the_namespace_and_window_count() {
        let mut other_class = receipt("op-chat", "a", Some(("allow", "acme", "v1")));
        other_class.operation_class = "chat".into();
        let mut other_namespace = receipt("op-beta", "a", Some(("allow", "acme", "v1")));
        other_namespace.namespace = "beta".into();
        let mut late = receipt("op-late", "a", Some(("allow", "acme", "v1")));
        late.started_at_ms = 300;
        late.completed_at_ms = Some(300);
        let report = run(
            &ActionPolicy::allow_all("acme"),
            &[other_class, other_namespace, late],
        );
        assert_eq!(report.counts.evaluated, 0);
    }
}
