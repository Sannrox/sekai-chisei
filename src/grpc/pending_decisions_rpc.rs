//! `ListPendingDecisions` (#2203): what waits on the caller's decision across
//! the four review kinds. Rows stay in each kind's store. Each kind is
//! filtered by the check its decide RPC applies, reused rather than
//! restated, so the list is exactly what that RPC would accept from this
//! caller:
//!
//! - parked Action instances: `DecideActionInstance`
//!   ([`namespace_decider`], [`visit_decidable_action_instances`]);
//! - plan reviews: `DecidePlanReview` ([`namespace_decider`],
//!   [`plan_review::check_decider`], [`plan_review_step_decider`]);
//! - definition proposals: `ApproveDefinitionProposal`
//!   ([`authorize_source_sync_namespace`],
//!   [`authorize_definition_proposal_approval`]), less those the caller
//!   already approved;
//! - dataset branch proposals: `MergeDatasetBranch`
//!   ([`may_merge_dataset_proposal`]).
//!
//! Every kind also passes the space role and credential scope of its decide
//! RPC ([`crate::grpc::authorize_rpc_space`]). A kind the caller may not
//! decide in contributes nothing, so a refusal and an empty queue look the
//! same. Freshness preconditions are left to the decide RPC.

use super::rpc_actions::{
    namespace_decider, plan_review_step_decider, visit_decidable_action_instances,
};
use super::rpc_data::{context_tenant, may_merge_dataset_proposal};
use super::rpc_definitions::authorize_definition_proposal_approval;
use super::*;
use crate::sekai::plan_review;

/// Store rows read per page while filtering.
const SCAN_PAGE: usize = 100;

/// Position after the last decision of a page: its kind, then its place in
/// that kind's newest-first order. It names only a decision the caller was
/// shown.
#[derive(Debug, PartialEq, Eq)]
struct Cursor {
    kind: i32,
    requested_at_ms: i64,
    subject_id: String,
}

impl Cursor {
    fn parse(token: &str) -> Result<Option<Self>, Status> {
        if token.is_empty() {
            return Ok(None);
        }
        let invalid = || Status::invalid_argument("invalid page_token");
        let mut parts = token.splitn(3, ':');
        let (Some(kind), Some(requested_at_ms), Some(subject_id)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        Ok(Some(Self {
            kind: kind.parse().map_err(|_| invalid())?,
            requested_at_ms: requested_at_ms.parse().map_err(|_| invalid())?,
            subject_id: subject_id.to_string(),
        }))
    }

    fn token(decision: &PendingDecision) -> String {
        format!(
            "{}:{}:{}",
            decision.kind, decision.requested_at_ms, decision.subject_id
        )
    }
}

/// The page being filled: decisions past the cursor, up to the limit.
struct Page {
    cursor: Option<Cursor>,
    limit: usize,
    decisions: Vec<PendingDecision>,
}

impl Page {
    fn full(&self) -> bool {
        self.decisions.len() >= self.limit
    }

    /// Whether a kind holds anything past the cursor.
    fn reaches(&self, kind: PendingDecisionKind) -> bool {
        self.cursor
            .as_ref()
            .is_none_or(|cursor| kind as i32 >= cursor.kind)
    }

    /// Whether `decision` comes after the cursor in response order.
    fn after_cursor(&self, decision: &PendingDecision) -> bool {
        self.cursor.as_ref().is_none_or(|cursor| {
            decision.kind > cursor.kind
                || (decision.kind == cursor.kind
                    && (decision.requested_at_ms, decision.subject_id.as_str())
                        < (cursor.requested_at_ms, cursor.subject_id.as_str()))
        })
    }

    /// Adds `decision`; false once the page is full.
    fn push(&mut self, decision: PendingDecision) -> bool {
        self.decisions.push(decision);
        !self.full()
    }
}

/// Whether a check's error is a refusal (`Ok(false)`); a store or
/// dependency failure stays an error.
fn refusal(status: Status) -> Result<bool, Status> {
    match status.code() {
        tonic::Code::Internal | tonic::Code::Unavailable => Err(status),
        _ => Ok(false),
    }
}

pub(super) async fn list_pending_decisions(
    service: &SekaiServiceImpl,
    req: Request<ListPendingDecisionsRequest>,
) -> Result<Response<ListPendingDecisionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let policy_context = principal_policy_context(&req);
    let input = req.get_ref();
    let namespace = input.namespace.as_str();
    if namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    let mut kinds = input
        .kinds
        .iter()
        .map(|&kind| {
            PendingDecisionKind::try_from(kind)
                .ok()
                .filter(|kind| *kind != PendingDecisionKind::Unspecified)
                .ok_or_else(|| Status::invalid_argument("unknown pending decision kind"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if kinds.is_empty() {
        kinds = vec![
            PendingDecisionKind::ActionInstance,
            PendingDecisionKind::PlanReview,
            PendingDecisionKind::DefinitionProposal,
            PendingDecisionKind::DatasetBranchProposal,
        ];
    }
    kinds.sort();
    kinds.dedup();
    let mut page = Page {
        cursor: Cursor::parse(&input.page_token)?,
        limit: (if input.limit == 0 {
            100
        } else {
            input.limit as usize
        })
        .clamp(1, 500),
        decisions: Vec::new(),
    };
    // The space role and credential scope of the kind's decide RPC.
    let space_allows = |method: &str| {
        tenant_context
            .as_ref()
            .is_none_or(|context| crate::grpc::authorize_rpc_space(context, method).is_ok())
    };
    for kind in kinds {
        if page.full() {
            break;
        }
        if !page.reaches(kind) {
            continue;
        }
        let context = tenant_context.as_ref();
        match kind {
            PendingDecisionKind::ActionInstance => {
                if space_allows("DecideActionInstance")
                    && let Some(decider) =
                        namespace_decider(service, &req, &principals, context, namespace)
                {
                    list_action_instances(service, &decider, namespace, &mut page)?;
                }
            }
            PendingDecisionKind::PlanReview => {
                if space_allows("DecidePlanReview")
                    && let Some(decider) =
                        namespace_decider(service, &req, &principals, context, namespace)
                {
                    let deciders = vec![decider.clone()];
                    let may_decide = plan_review_step_decider(
                        service,
                        &decider,
                        &deciders,
                        context,
                        &policy_context,
                        now_millis(),
                    );
                    list_plan_reviews(service, &decider, &may_decide, namespace, &mut page)?;
                }
            }
            PendingDecisionKind::DefinitionProposal => {
                if space_allows("ApproveDefinitionProposal")
                    && authorize_source_sync_namespace(
                        service,
                        &principals,
                        context,
                        namespace,
                        true,
                    )
                    .map(|()| true)
                    .or_else(refusal)?
                {
                    list_definition_proposals(service, &principals, namespace, &mut page)?;
                }
            }
            PendingDecisionKind::DatasetBranchProposal => {
                if space_allows("MergeDatasetBranch") {
                    list_dataset_proposals(service, &principals, context, namespace, &mut page)?;
                }
            }
            PendingDecisionKind::Unspecified => {}
        }
    }
    let next_page_token = if page.full() {
        page.decisions.last().map(Cursor::token).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Response::new(ListPendingDecisionsResponse {
        decisions: page.decisions,
        next_page_token,
    }))
}

fn list_action_instances(
    service: &SekaiServiceImpl,
    decider: &str,
    namespace: &str,
    page: &mut Page,
) -> Result<(), Status> {
    visit_decidable_action_instances(service, decider, namespace, None, |instance| {
        let decision = PendingDecision {
            kind: PendingDecisionKind::ActionInstance.into(),
            namespace: instance.namespace.clone(),
            subject_id: instance.instance_id.clone(),
            subject_digest: instance.request_digest.clone(),
            requested_by: instance.principal.clone(),
            requested_at_ms: instance.created_at_ms,
            deadline_ms: instance.review.sla_deadline_ms,
            queue_id: instance.review.queue_id.clone(),
            dataset_id: String::new(),
        };
        !page.after_cursor(&decision) || page.push(decision)
    })
}

fn list_plan_reviews(
    service: &SekaiServiceImpl,
    decider: &str,
    may_decide: &dyn Fn(
        &crate::sekai::action_plan::ProposedPlan,
        &crate::sekai::action_plan::PlanStep,
    ) -> bool,
    namespace: &str,
    page: &mut Page,
) -> Result<(), Status> {
    let db = service.db.runtime();
    let mut offset = 0;
    loop {
        let reviews = db
            .list_pending_plan_reviews(namespace, SCAN_PAGE, offset)
            .map_err(Status::internal)?;
        offset += reviews.len();
        for review in &reviews {
            let decision = PendingDecision {
                kind: PendingDecisionKind::PlanReview.into(),
                namespace: review.namespace.clone(),
                subject_id: review.plan_id.clone(),
                subject_digest: review.simulation_digest.clone(),
                requested_by: review.submitted_by.clone(),
                requested_at_ms: review.submitted_at_ms,
                deadline_ms: 0,
                // A decider may read every step's object.
                queue_id: review
                    .queue_ids(|_| false)
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
                dataset_id: String::new(),
            };
            if !page.after_cursor(&decision) {
                continue;
            }
            let Some(plan) = db
                .get_plan(namespace, &review.plan_id)
                .map_err(Status::internal)?
            else {
                continue;
            };
            if plan_review::check_decider(&plan, decider, may_decide).is_ok()
                && !page.push(decision)
            {
                return Ok(());
            }
        }
        if reviews.len() < SCAN_PAGE {
            return Ok(());
        }
    }
}

fn list_definition_proposals(
    service: &SekaiServiceImpl,
    principals: &[String],
    namespace: &str,
    page: &mut Page,
) -> Result<(), Status> {
    let db = service.db.runtime();
    let mut offset = 0;
    loop {
        let proposals = db
            .list_open_definition_proposals(namespace, SCAN_PAGE, offset)
            .map_err(Status::internal)?;
        offset += proposals.len();
        for proposal in &proposals {
            let decision = PendingDecision {
                kind: PendingDecisionKind::DefinitionProposal.into(),
                namespace: proposal.namespace.clone(),
                subject_id: proposal.proposal_id.clone(),
                subject_digest: proposal.proposal_digest.clone(),
                requested_by: proposal.created_by.clone(),
                requested_at_ms: proposal.created_at_ms,
                deadline_ms: 0,
                queue_id: String::new(),
                dataset_id: String::new(),
            };
            if !page.after_cursor(&decision) {
                continue;
            }
            // An approval the caller already gave is not pending on them.
            let pending =
                match authorize_definition_proposal_approval(service, principals, proposal) {
                    Ok(actor) => !proposal
                        .approvals
                        .iter()
                        .any(|approval| approval.actor == actor),
                    Err(status) => refusal(status)?,
                };
            if pending && !page.push(decision) {
                return Ok(());
            }
        }
        if proposals.len() < SCAN_PAGE {
            return Ok(());
        }
    }
}

fn list_dataset_proposals(
    service: &SekaiServiceImpl,
    principals: &[String],
    context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    page: &mut Page,
) -> Result<(), Status> {
    let db = service.db.runtime();
    let tenant = context_tenant(context);
    let mut offset = 0;
    loop {
        let proposals = db
            .list_open_dataset_branch_proposals(&tenant, SCAN_PAGE, offset)
            .map_err(Status::internal)?;
        offset += proposals.len();
        for (proposal, attached) in &proposals {
            let decision = PendingDecision {
                kind: PendingDecisionKind::DatasetBranchProposal.into(),
                namespace: namespace.to_string(),
                subject_id: proposal.id.clone(),
                subject_digest: proposal.branch_digest.clone(),
                requested_by: proposal.proposer.clone(),
                requested_at_ms: proposal.created_at_ms,
                deadline_ms: 0,
                queue_id: String::new(),
                dataset_id: proposal.dataset_id.clone(),
            };
            if page.after_cursor(&decision)
                && may_merge_dataset_proposal(
                    service, principals, context, namespace, proposal, *attached,
                )?
                && !page.push(decision)
            {
                return Ok(());
            }
        }
        if proposals.len() < SCAN_PAGE {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(kind: PendingDecisionKind, at: i64, id: &str) -> PendingDecision {
        PendingDecision {
            kind: kind.into(),
            requested_at_ms: at,
            subject_id: id.into(),
            ..PendingDecision::default()
        }
    }

    /// A token resumes strictly after the decision it names, in kind order
    /// then newest first.
    #[test]
    fn a_page_token_resumes_after_its_decision() {
        let last = decision(PendingDecisionKind::PlanReview, 20, "plan:b");
        let page = Page {
            cursor: Cursor::parse(&Cursor::token(&last)).unwrap(),
            limit: 10,
            decisions: Vec::new(),
        };
        assert!(!page.reaches(PendingDecisionKind::ActionInstance));
        assert!(page.reaches(PendingDecisionKind::PlanReview));
        assert!(!page.after_cursor(&last));
        assert!(!page.after_cursor(&decision(PendingDecisionKind::PlanReview, 30, "a")));
        assert!(!page.after_cursor(&decision(PendingDecisionKind::PlanReview, 20, "plan:c")));
        assert!(page.after_cursor(&decision(PendingDecisionKind::PlanReview, 20, "plan:a")));
        assert!(page.after_cursor(&decision(PendingDecisionKind::PlanReview, 10, "z")));
        assert!(page.after_cursor(&decision(PendingDecisionKind::DefinitionProposal, 99, "z")));
        for token in ["x", "1:2", "a:2:id", "1:b:id"] {
            assert!(Cursor::parse(token).is_err(), "{token}");
        }
    }
}
