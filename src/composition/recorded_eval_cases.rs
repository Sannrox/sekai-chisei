//! Recorded eval cases (ADR 0153, #3513): freezing decided Action instances
//! into a dataset version, checking that each source still stands, and
//! replaying each case through the agent dry run.
//!
//! Every Sekai read goes through the Sekai service as the original caller
//! (`SekaiServiceImpl::caller_reads_action_instance`, `caller_dry_run_turn`),
//! so a recorded dataset never shows or runs more than that caller could read.
//! Nothing here copies a parameter or property value into the eval store: the
//! case input is rebuilt from the instance and the change log for each run
//! and dropped after it. Combined mode only; a Chisei plane without the Sekai
//! service refuses recorded datasets.

use std::collections::HashMap;

use tonic::{Request, Status};

use crate::chisei::eval_dataset::recorded::{
    DECISION_DENY, DECISION_GRANT, RecordedCase, RecordedDatasetSelection,
    RecordedEvalDatasetDefinition,
};
use crate::chisei::eval_dataset::{DATASET_NOT_FOUND, EvalCase, EvalDataset};
use crate::chisei::eval_policy::{ActionReceipt, CaseReceipts, ToolCallReceipt};
use crate::chisei::eval_run::{CaseError, CaseOutcome, EvalCaseExecutor, EvalRunSpec};
use crate::grpc::sekai_service::SekaiServiceImpl;
use crate::sekai::action_instance::{
    ActionInstance, DECISION_DENY as INSTANCE_DENY, DECISION_GRANT as INSTANCE_GRANT,
    STATUS_ADMITTED, STATUS_DENIED, compute_request_digest_with_envelope,
};
use crate::sekai::agent_dry_run::{DISPOSITION_WOULD_SUBMIT, DryRunTrace};

/// Instances read per page while selecting.
const SCAN_PAGE: usize = 500;
/// The most instances one selection reads before it refuses.
const MAX_SCANNED: usize = 50_000;
/// The deny reason of an approver's deny; other denies after a grant are
/// system outcomes (`stale_on_resume` and the like) and yield no case.
const DENIED_BY_APPROVER: &str = "denied_by_approver";
/// Plan steps are decided by one review over the bundle (ADR 0153 rule 2).
const PLAN_STEP_PREFIX: &str = "plan:";

pub const RECORDED_NEEDS_COMBINED: &str =
    "recorded eval datasets need the Sekai plane in this process";
/// `agent` of a recorded run: `<member_id>@<revision_digest>`.
pub const AGENT_FORMAT: &str = "a recorded run names its agent as <member_id>@<revision_digest>";

/// The decision a person made on `instance`, when it yields a case: it parked
/// for approval, a person decided it, and the outcome is that decision. Policy
/// outcomes, system outcomes after a grant, plan steps and offline
/// submissions (whose digest folds in the offline envelope) yield none.
pub fn human_decision(instance: &ActionInstance) -> Option<&'static str> {
    if instance.approval.is_none()
        || instance.decided_by.trim().is_empty()
        || instance.offline.is_some()
        || instance.idempotency_key.starts_with(PLAN_STEP_PREFIX)
    {
        return None;
    }
    match (
        instance.status.as_str(),
        instance.approval_decision.as_str(),
    ) {
        (STATUS_ADMITTED, INSTANCE_GRANT) => Some(DECISION_GRANT),
        (STATUS_DENIED, INSTANCE_DENY) if instance.deny_reason == DENIED_BY_APPROVER => {
            Some(DECISION_DENY)
        }
        _ => None,
    }
}

/// Whether `instance`'s stored parameters still produce `request_digest`.
/// Erasure rewrites parameters in place and keeps the digest, so this is what
/// tells an erased or rewritten source from an intact one.
fn digest_still_matches(instance: &ActionInstance, request_digest: &str) -> bool {
    instance.erased_properties.is_empty()
        && instance.request_digest == request_digest
        && compute_request_digest_with_envelope(
            &instance.namespace,
            &instance.type_id,
            &instance.version,
            &instance.parameters_json,
            &instance.evidence_submission_ids,
            &instance.autonomous_envelope_id,
        )
        .is_ok_and(|digest| digest == request_digest)
}

/// Whether `instance` is still the source `case` references.
fn source_matches(
    instance: &ActionInstance,
    namespace: &str,
    action_type: &str,
    case: &RecordedCase,
) -> bool {
    instance.namespace == namespace
        && instance.type_id == action_type
        && instance.decided_at_ms == case.decided_at_ms
        && human_decision(instance) == Some(case.decision.as_str())
        && digest_still_matches(instance, &case.request_digest)
}

/// The caller of `request` as the Sekai gates read it: the metadata the
/// interceptor wrote and the request extensions, nothing the caller sent.
pub fn caller_of<T>(request: &Request<T>) -> Request<()> {
    let mut caller = Request::new(());
    for key in crate::grpc::AUTHENTICATED_METADATA {
        if let Some(value) = request.metadata().get(key) {
            caller.metadata_mut().insert(key, value.clone());
        }
    }
    *caller.extensions_mut() = request.extensions().clone();
    caller
}

/// The decided instances of `namespace` that `selection` admits and the
/// caller can read, as case references. An unreadable instance is skipped
/// exactly like one that does not match.
pub fn select_cases(
    sekai: &SekaiServiceImpl,
    caller: &Request<()>,
    namespace: &str,
    selection: &RecordedDatasetSelection,
) -> Result<Vec<RecordedCase>, Status> {
    let store = sekai.recorded_case_store();
    let mut cases = Vec::new();
    let mut scanned = 0;
    // Newest first; an instance created at or after the window's end cannot
    // have been decided inside it.
    let mut cursor: Option<(i64, String)> = None;
    loop {
        let (at_ms, id) = cursor
            .clone()
            .unwrap_or((selection.decided_to_ms, String::new()));
        let page = store
            .list_action_instances_between(
                namespace,
                Some(&selection.action_type),
                None,
                0,
                crate::db::OlderThan { at_ms, id: &id },
                SCAN_PAGE,
            )
            .map_err(Status::internal)?;
        scanned += page.len();
        if scanned > MAX_SCANNED {
            return Err(Status::failed_precondition(
                "the window holds too many instances to select from; narrow it",
            ));
        }
        for instance in &page {
            let Some(decision) = human_decision(instance) else {
                continue;
            };
            if !selection.admits(decision, instance.decided_at_ms)
                || !digest_still_matches(instance, &instance.request_digest)
                || !sekai.caller_reads_action_instance(caller, instance)?
            {
                continue;
            }
            cases.push(RecordedCase {
                instance_id: instance.instance_id.clone(),
                request_digest: instance.request_digest.clone(),
                decision: decision.into(),
                decided_at_ms: instance.decided_at_ms,
            });
        }
        match page.last() {
            Some(last) if page.len() == SCAN_PAGE => {
                cursor = Some((last.created_at_ms, last.instance_id.clone()));
            }
            _ => return Ok(cases),
        }
    }
}

/// The instance behind every case, in case order, or "not found" when any
/// source was deleted, erased, redacted or rewritten: a version whose sources
/// do not all stand no longer resolves (ADR 0153 rule 6).
pub fn sources(
    sekai: &SekaiServiceImpl,
    namespace: &str,
    definition: &RecordedEvalDatasetDefinition,
) -> Result<Vec<ActionInstance>, Status> {
    let store = sekai.recorded_case_store();
    definition
        .cases
        .iter()
        .map(|case| {
            store
                .get_action_instance(&case.instance_id)
                .map_err(Status::internal)?
                .filter(|instance| {
                    source_matches(instance, namespace, &definition.selection.action_type, case)
                })
                .ok_or_else(|| Status::not_found(DATASET_NOT_FOUND))
        })
        .collect()
}

/// Whether the caller can read each source, in order.
pub fn readable(
    sekai: &SekaiServiceImpl,
    caller: &Request<()>,
    sources: &[ActionInstance],
) -> Result<Vec<bool>, Status> {
    sources
        .iter()
        .map(|instance| sekai.caller_reads_action_instance(caller, instance))
        .collect()
}

/// `(member_id, revision_digest)` from a recorded run's `agent`.
pub fn parse_agent(agent: &str) -> Result<(&str, &str), Status> {
    agent
        .split_once('@')
        .filter(|(member, revision)| !member.is_empty() && !revision.is_empty())
        .ok_or_else(|| Status::invalid_argument(AGENT_FORMAT))
}

/// Runs recorded cases as dry-run turns of one agent revision, as the caller.
/// Built by [`RecordedCaseExecutor::prepare`], which refuses the whole run
/// unless every case resolves and is readable: a run is never scored on fewer
/// cases (ADR 0153 rule 5).
pub struct RecordedCaseExecutor<'a> {
    sekai: &'a SekaiServiceImpl,
    caller: Request<()>,
    namespace: String,
    member_id: String,
    revision_digest: String,
    /// Per case id: the source and the turn input rebuilt from it. Held for
    /// the run only, never stored.
    cases: HashMap<String, (ActionInstance, String)>,
}

impl<'a> RecordedCaseExecutor<'a> {
    pub fn prepare(
        sekai: &'a SekaiServiceImpl,
        caller: Request<()>,
        namespace: &str,
        definition: &RecordedEvalDatasetDefinition,
        agent: &str,
    ) -> Result<Self, Status> {
        let (member_id, revision_digest) = parse_agent(agent)?;
        let sources = sources(sekai, namespace, definition)?;
        if readable(sekai, &caller, &sources)?.contains(&false) {
            return Err(Status::not_found(DATASET_NOT_FOUND));
        }
        let (live, changes) = sekai.namespace_object_history(namespace)?;
        let mut cases = HashMap::new();
        for instance in sources {
            let input = turn_input(namespace, &instance, &live, &changes)
                .ok_or_else(|| Status::not_found(DATASET_NOT_FOUND))?;
            cases.insert(instance.instance_id.clone(), (instance, input));
        }
        Ok(Self {
            sekai,
            caller,
            namespace: namespace.into(),
            member_id: member_id.into(),
            revision_digest: revision_digest.into(),
            cases,
        })
    }
}

/// What the agent sees for one case: the Action type, the instance's stored
/// parameters and its target object as of the proposal, rebuilt from the
/// change log. `None` when the history no longer reaches the proposal or the
/// target cannot be rebuilt.
fn turn_input(
    namespace: &str,
    instance: &ActionInstance,
    live: &[crate::domain::Object],
    changes: &[crate::sekai::object_change_subscription::CommittedObjectMutation],
) -> Option<String> {
    use crate::sekai::counterfactual::{history_covers, objects_as_of};
    let parameters: serde_json::Value = serde_json::from_str(&instance.parameters_json).ok()?;
    let object = match parameters
        .get("object_id")
        .and_then(serde_json::Value::as_str)
    {
        Some(object_id) => {
            if !history_covers(changes, instance.created_at_ms) {
                return None;
            }
            let live: Vec<_> = live
                .iter()
                .filter(|object| object.id == object_id)
                .cloned()
                .collect();
            let changes: Vec<_> = changes
                .iter()
                .filter(|mutation| mutation.change.object_id == object_id)
                .cloned()
                .collect();
            let as_of = objects_as_of(namespace, &live, &changes, instance.created_at_ms);
            if as_of.unreconstructable.iter().any(|id| id == object_id) {
                return None;
            }
            as_of
                .objects
                .into_iter()
                .find(|object| object.id == object_id)
                .map(|object| serde_json::to_value(object).ok())
                .unwrap_or(Some(serde_json::Value::Null))?
        }
        None => serde_json::Value::Null,
    };
    Some(
        serde_json::json!({
            "action_type": instance.type_id,
            "parameters": parameters,
            "object": object,
        })
        .to_string(),
    )
}

/// Whether `trace` would submit the Action `instance` requested: the same
/// type, and parameters that give the instance's request digest under its
/// version, evidence and envelope.
fn proposes(trace: &DryRunTrace, instance: &ActionInstance) -> bool {
    trace.actions.iter().any(|action| {
        action.disposition == DISPOSITION_WOULD_SUBMIT
            && action.action_type == instance.type_id
            && compute_request_digest_with_envelope(
                &instance.namespace,
                &instance.type_id,
                &instance.version,
                &action.parameters_json,
                &instance.evidence_submission_ids,
                &instance.autonomous_envelope_id,
            )
            .is_ok_and(|digest| digest == instance.request_digest)
    })
}

/// The verdict for a case: a grant expects the Action proposed, a deny
/// expects it not proposed. Reasons are fixed strings, never values.
fn verdict(expected: &str, proposed: bool) -> (bool, &'static str) {
    match (expected == DECISION_GRANT, proposed) {
        (true, true) => (true, "proposed the granted action"),
        (true, false) => (false, "did not propose the granted action"),
        (false, true) => (false, "proposed the denied action"),
        (false, false) => (true, "did not propose the denied action"),
    }
}

impl EvalCaseExecutor for RecordedCaseExecutor<'_> {
    fn run_case(
        &self,
        _spec: &EvalRunSpec,
        _dataset: &EvalDataset,
        case: &EvalCase,
    ) -> Result<CaseOutcome, CaseError> {
        let (instance, input) = self
            .cases
            .get(&case.case_id)
            .ok_or_else(|| CaseError::NothingSpent(DATASET_NOT_FOUND.into()))?;
        let trace = self
            .sekai
            .caller_dry_run_turn(
                &self.caller,
                &self.namespace,
                &self.revision_digest,
                &self.member_id,
                input.clone(),
            )
            // A refused turn charged nothing it reports; the host owns
            // budget admission.
            .map_err(|status| CaseError::NothingSpent(status.message().to_string()))?;
        let (passed, reason) = verdict(&case.expected, proposes(&trace, instance));
        // The policy scorer reads the dry-run trace: what the turn called and
        // what it would have submitted, never applied.
        let receipts = CaseReceipts {
            tool_calls: trace
                .tool_calls
                .iter()
                .enumerate()
                .map(|(index, call)| ToolCallReceipt {
                    receipt_id: format!("dry-run:{}:tool:{index}", case.case_id),
                    tool: call.name.clone(),
                })
                .collect(),
            outputs: Vec::new(),
            actions: trace
                .actions
                .iter()
                .enumerate()
                .filter(|(_, action)| action.disposition == DISPOSITION_WOULD_SUBMIT)
                .map(|(index, action)| ActionReceipt {
                    receipt_id: format!("dry-run:{}:action:{index}", case.case_id),
                    action_type: action.action_type.clone(),
                    applied: false,
                    approval_receipt_id: None,
                })
                .collect(),
        };
        Ok(CaseOutcome {
            passed,
            reason: reason.into(),
            trial_code: None,
            unmet_metrics: Vec::new(),
            input_tokens: 0,
            output_tokens: 0,
            cost_micros: 0,
            receipts: Some(receipts),
            policy: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_expects_exactly_the_decided_action() {
        assert_eq!(
            verdict(DECISION_GRANT, true),
            (true, "proposed the granted action")
        );
        assert!(!verdict(DECISION_GRANT, false).0);
        assert!(!verdict(DECISION_DENY, true).0);
        assert!(
            verdict(DECISION_DENY, false).0,
            "proposing nothing passes a deny"
        );
    }

    #[test]
    fn the_agent_names_a_member_at_a_revision() {
        assert_eq!(
            parse_agent("triage@sha256:abc").unwrap(),
            ("triage", "sha256:abc")
        );
        assert!(parse_agent("triage").is_err());
        assert!(parse_agent("@sha256:abc").is_err());
    }
}
