//! Review queues for parked Action instances (#1455).
//!
//! A governed Action type may name a queue, SLA, threshold, pool, and
//! escalation. Parking routes matching instances onto that queue. Decide
//! stays the existing approval RPC; a reviewer outside the pool cannot
//! decide. Past-SLA items escalate by reassignment or auto-deny.

use serde::{Deserialize, Serialize};

pub const ESCALATE_AUTO_DENY: &str = "auto_deny";
pub const ESCALATE_REASSIGN: &str = "reassign";

/// Queue configuration stored on a governed Action type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewQueueSpec {
    /// Empty means parked instances stay on the type's approver list only.
    #[serde(default)]
    pub queue_id: String,
    /// 0 means no deadline.
    #[serde(default)]
    pub sla_ms: i64,
    /// `auto_deny` or `reassign`. Empty means no escalation.
    #[serde(default)]
    pub escalate: String,
    /// Principal who receives a reassigned item.
    #[serde(default)]
    pub escalate_to: String,
    /// Parameter name whose numeric value is compared to `threshold`.
    /// Empty means every parked instance of this type routes to the queue.
    #[serde(default)]
    pub threshold_param: String,
    /// Inclusive lower bound. 0 with an empty param still routes every park.
    #[serde(default)]
    pub threshold: i64,
    /// Reviewers who may decide a queued item. Empty uses the type approvers as the pool.
    #[serde(default)]
    pub pool: Vec<String>,
    /// Subset of `pool` whose decisions are marked as agent decisions.
    #[serde(default)]
    pub agent_reviewers: Vec<String>,
}

/// Placement recorded on a parked Action instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewPlacement {
    #[serde(default)]
    pub queue_id: String,
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub sla_deadline_ms: i64,
    #[serde(default)]
    pub escalated: bool,
    #[serde(default)]
    pub agent_decision: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Escalation {
    None,
    Reassign { assignee: String },
    AutoDeny,
}

impl ReviewQueueSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.queue_id.trim().is_empty() {
            return Ok(());
        }
        if self.queue_id.chars().any(char::is_whitespace) {
            return Err("review queue_id must not contain whitespace".into());
        }
        if self.sla_ms < 0 {
            return Err("review sla_ms must be >= 0".into());
        }
        if self.threshold < 0 {
            return Err("review threshold must be >= 0".into());
        }
        match self.escalate.as_str() {
            "" | ESCALATE_AUTO_DENY | ESCALATE_REASSIGN => {}
            other => {
                return Err(format!(
                    "review escalate must be {ESCALATE_AUTO_DENY}, {ESCALATE_REASSIGN}, or empty, not {other}"
                ));
            }
        }
        if self.escalate == ESCALATE_REASSIGN && self.escalate_to.trim().is_empty() {
            return Err("review escalate_to is required for reassign".into());
        }
        if self
            .pool
            .iter()
            .chain(self.agent_reviewers.iter())
            .any(|principal| {
                principal.trim().is_empty() || principal.chars().any(char::is_whitespace)
            })
        {
            return Err("review pool principals must be non-empty without whitespace".into());
        }
        if self
            .agent_reviewers
            .iter()
            .any(|principal| !self.pool.is_empty() && !self.pool.contains(principal))
        {
            return Err("agent reviewers must be members of the review pool".into());
        }
        Ok(())
    }

    pub fn validate_with_approvers(&self, approvers: &[String]) -> Result<(), String> {
        self.validate()?;
        if !self.active() || approvers.is_empty() {
            return Ok(());
        }
        let entitled = |principal: &str| approvers.iter().any(|approver| approver == principal);
        if self.pool.iter().any(|principal| !entitled(principal)) {
            return Err("review pool members must be type approvers".into());
        }
        if self.escalate == ESCALATE_REASSIGN && !entitled(&self.escalate_to) {
            return Err("review escalate_to must be a type approver".into());
        }
        Ok(())
    }

    pub fn active(&self) -> bool {
        !self.queue_id.trim().is_empty()
    }
}

/// Whether a parked instance of this type belongs on the named queue.
pub fn routes_to_queue(spec: &ReviewQueueSpec, parameters_json: &str) -> bool {
    if !spec.active() {
        return false;
    }
    if spec.threshold_param.trim().is_empty() {
        return true;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(parameters_json) else {
        return false;
    };
    let Some(raw) = value.get(spec.threshold_param.trim()) else {
        return false;
    };
    json_amount(raw).is_some_and(|amount| amount >= spec.threshold as f64)
}

fn json_amount(raw: &serde_json::Value) -> Option<f64> {
    raw.as_f64()
        .or_else(|| raw.as_i64().map(|n| n as f64))
        .or_else(|| raw.as_u64().map(|n| n as f64))
        .filter(|amount| amount.is_finite())
}

pub fn place(
    spec: &ReviewQueueSpec,
    parameters_json: &str,
    now_ms: i64,
    submitter: &str,
    approvers: &[String],
) -> ReviewPlacement {
    if !routes_to_queue(spec, parameters_json) {
        return ReviewPlacement::default();
    }
    let pool = if spec.pool.is_empty() {
        approvers
    } else {
        spec.pool.as_slice()
    };
    let assignee = pool
        .iter()
        .find(|principal| principal.as_str() != submitter)
        .cloned()
        .unwrap_or_default();
    ReviewPlacement {
        queue_id: spec.queue_id.clone(),
        assignee,
        sla_deadline_ms: if spec.sla_ms > 0 {
            now_ms.saturating_add(spec.sla_ms)
        } else {
            0
        },
        escalated: false,
        agent_decision: false,
    }
}

/// Queue membership is an extra gate on top of the type's approver list.
pub fn reviewer_may_decide(
    spec: &ReviewQueueSpec,
    placement: &ReviewPlacement,
    decider: &str,
) -> bool {
    if placement.queue_id.is_empty() {
        return true;
    }
    if !placement.assignee.is_empty() {
        return decider == placement.assignee;
    }
    if spec.pool.is_empty() {
        return true;
    }
    spec.pool.iter().any(|principal| principal == decider)
}

pub fn mark_decision(
    spec: &ReviewQueueSpec,
    placement: &ReviewPlacement,
    decider: &str,
) -> ReviewPlacement {
    let mut next = placement.clone();
    next.agent_decision = spec
        .agent_reviewers
        .iter()
        .any(|principal| principal == decider);
    next
}

pub fn due_for_escalation(
    spec: &ReviewQueueSpec,
    placement: &ReviewPlacement,
    now_ms: i64,
) -> bool {
    spec.active()
        && !placement.queue_id.is_empty()
        && !placement.escalated
        && placement.sla_deadline_ms > 0
        && now_ms >= placement.sla_deadline_ms
        && matches!(
            spec.escalate.as_str(),
            ESCALATE_AUTO_DENY | ESCALATE_REASSIGN
        )
}

pub fn escalate(spec: &ReviewQueueSpec, placement: &ReviewPlacement, now_ms: i64) -> Escalation {
    if !due_for_escalation(spec, placement, now_ms) {
        return Escalation::None;
    }
    match spec.escalate.as_str() {
        ESCALATE_AUTO_DENY => Escalation::AutoDeny,
        ESCALATE_REASSIGN => Escalation::Reassign {
            assignee: spec.escalate_to.clone(),
        },
        _ => Escalation::None,
    }
}

pub fn apply_reassign(placement: &ReviewPlacement, assignee: &str) -> ReviewPlacement {
    ReviewPlacement {
        queue_id: placement.queue_id.clone(),
        assignee: assignee.to_string(),
        sla_deadline_ms: placement.sla_deadline_ms,
        escalated: true,
        agent_decision: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spend_queue() -> ReviewQueueSpec {
        ReviewQueueSpec {
            queue_id: "spend".into(),
            sla_ms: 1_000,
            escalate: ESCALATE_AUTO_DENY.into(),
            escalate_to: String::new(),
            threshold_param: "amount".into(),
            threshold: 100,
            pool: vec!["bob".into(), "agent.review".into()],
            agent_reviewers: vec!["agent.review".into()],
        }
    }

    #[test]
    fn below_threshold_stays_off_the_queue() {
        let spec = spend_queue();
        assert!(!routes_to_queue(&spec, r#"{"amount":50}"#));
        assert_eq!(
            place(&spec, r#"{"amount":50}"#, 10, "alice", &[]),
            ReviewPlacement::default()
        );
    }

    #[test]
    fn over_threshold_routes_to_the_named_queue() {
        let spec = spend_queue();
        assert!(routes_to_queue(&spec, r#"{"amount":100.5}"#));
        assert!(routes_to_queue(&spec, r#"{"amount":9223372036854775808}"#));
        let placed = place(&spec, r#"{"amount":100}"#, 10, "alice", &[]);
        assert_eq!(placed.queue_id, "spend");
        assert_eq!(placed.assignee, "bob");
        assert_eq!(
            place(&spec, r#"{"amount":100}"#, 10, "bob", &[]).assignee,
            "agent.review"
        );
        assert_eq!(placed.sla_deadline_ms, 1_010);
    }

    #[test]
    fn reviewer_outside_the_assignee_cannot_decide() {
        let spec = spend_queue();
        let placed = place(&spec, r#"{"amount":250}"#, 10, "alice", &[]);
        assert!(reviewer_may_decide(&spec, &placed, "bob"));
        assert!(!reviewer_may_decide(&spec, &placed, "carol"));
        assert!(!reviewer_may_decide(&spec, &placed, "agent.review"));
    }

    #[test]
    fn agent_decision_is_marked_only_for_named_agent_reviewers() {
        let spec = spend_queue();
        let placed = ReviewPlacement {
            queue_id: "spend".into(),
            assignee: "agent.review".into(),
            ..ReviewPlacement::default()
        };
        assert!(mark_decision(&spec, &placed, "agent.review").agent_decision);
        assert!(!mark_decision(&spec, &placed, "bob").agent_decision);
    }

    #[test]
    fn past_sla_auto_denies() {
        let spec = spend_queue();
        let placed = place(&spec, r#"{"amount":250}"#, 10, "alice", &[]);
        assert_eq!(escalate(&spec, &placed, 1_009), Escalation::None);
        assert_eq!(escalate(&spec, &placed, 1_010), Escalation::AutoDeny);
    }

    #[test]
    fn past_sla_reassigns_to_the_configured_principal() {
        let mut spec = spend_queue();
        spec.escalate = ESCALATE_REASSIGN.into();
        spec.escalate_to = "eve".into();
        let placed = place(&spec, r#"{"amount":250}"#, 10, "alice", &[]);
        assert_eq!(
            escalate(&spec, &placed, 5_000),
            Escalation::Reassign {
                assignee: "eve".into()
            }
        );
        let next = apply_reassign(&placed, "eve");
        assert!(next.escalated);
        assert_eq!(next.assignee, "eve");
        assert!(reviewer_may_decide(&spec, &next, "eve"));
        assert!(!reviewer_may_decide(&spec, &next, "bob"));
    }

    #[test]
    fn reassign_requires_a_target() {
        let mut spec = spend_queue();
        spec.escalate = ESCALATE_REASSIGN.into();
        assert!(spec.validate().is_err());
    }
}
