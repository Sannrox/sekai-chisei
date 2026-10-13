//! ADR 0079 certification gate for agent-definition promotion (#1353).
//!
//! Merging a proposal that changes an agent-definition member requires a
//! current, non-revoked, baseline-passing certification bound to the
//! candidate revision. Missing, stale, failed, or revoked evidence is deny.
//! Certification is not a runtime grant. The bound record is a snapshot of
//! suite identity and pass/fail results; merge does not re-run evaluations.

use crate::sekai::definition_branch::DefinitionRevisionMember;

pub const AGENT_PROMOTION_CONTRACT: &str = "sekai.agent-definition-promotion/v1";
pub const MEMBER_KIND_AGENT: &str = "agent";
pub const STATUS_PASS: &str = "pass";
pub const STATUS_FAIL: &str = "fail";
pub const STATUS_MISSING: &str = "missing";
pub const STATUS_STALE: &str = "stale";
pub const STATUS_REVOKED: &str = "revoked";
pub const STATUS_ADMITTED: &str = "admitted";
pub const STATUS_NOT_REQUIRED: &str = "not_required";
pub const REFUSAL_MISSING: &str = "agent_promotion_requires_certification";
pub const REFUSAL_REVOKED: &str = "agent_promotion_certification_revoked";
pub const REFUSAL_STALE: &str = "agent_promotion_certification_stale";
pub const REFUSAL_FAILED: &str = "agent_promotion_certification_failed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDefinitionCertification {
    pub namespace: String,
    pub revision_digest: String,
    pub suite_id: String,
    pub certification_id: String,
    pub baseline_status: String,
    pub latest_status: String,
    pub expires_at_ms: i64,
    pub revoked_at_ms: i64,
    pub bound_by: String,
    pub bound_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPromotionGate {
    pub namespace: String,
    pub revision_digest: String,
    pub suite_id: String,
    pub certification_id: String,
    pub certification_status: String,
    pub baseline_status: String,
    pub latest_status: String,
    pub expires_at_ms: i64,
    pub admitted: bool,
    pub refusal: String,
}

pub fn agent_members_changed(
    from: &[DefinitionRevisionMember],
    to: &[DefinitionRevisionMember],
) -> bool {
    let from_agents = agent_pins(from);
    let to_agents = agent_pins(to);
    from_agents != to_agents
}

fn agent_pins(members: &[DefinitionRevisionMember]) -> Vec<(String, String)> {
    let mut pins = members
        .iter()
        .filter(|member| member.member_kind == MEMBER_KIND_AGENT)
        .map(|member| (member.member_id.clone(), member.member_digest.clone()))
        .collect::<Vec<_>>();
    pins.sort();
    pins
}

impl AgentDefinitionCertification {
    pub fn validate(&self) -> Result<(), String> {
        if self.namespace.trim().is_empty() || self.namespace.trim() != self.namespace {
            return Err("canonical namespace required".into());
        }
        if self.revision_digest.trim().is_empty() {
            return Err("revision_digest is required".into());
        }
        if self.suite_id.trim().is_empty() {
            return Err("suite_id is required".into());
        }
        if self.certification_id.trim().is_empty() {
            return Err("certification_id is required".into());
        }
        for (label, value) in [
            ("baseline_status", self.baseline_status.as_str()),
            ("latest_status", self.latest_status.as_str()),
        ] {
            if value != STATUS_PASS && value != STATUS_FAIL {
                return Err(format!("{label} must be pass or fail"));
            }
        }
        if self.expires_at_ms <= 0 {
            return Err("expires_at_ms must be positive".into());
        }
        if self.revoked_at_ms < 0 {
            return Err("revoked_at_ms must not be negative".into());
        }
        if self.bound_by.trim().is_empty() {
            return Err("bound_by is required".into());
        }
        if self.bound_at_ms <= 0 {
            return Err("bound_at_ms must be positive".into());
        }
        Ok(())
    }

    pub fn gate(&self, now_ms: i64) -> AgentPromotionGate {
        let (status, refusal, admitted) = if self.revoked_at_ms > 0 {
            (STATUS_REVOKED, REFUSAL_REVOKED, false)
        } else if self.expires_at_ms <= now_ms {
            (STATUS_STALE, REFUSAL_STALE, false)
        } else if self.baseline_status != STATUS_PASS || self.latest_status != STATUS_PASS {
            (STATUS_FAIL, REFUSAL_FAILED, false)
        } else {
            (STATUS_ADMITTED, "", true)
        };
        AgentPromotionGate {
            namespace: self.namespace.clone(),
            revision_digest: self.revision_digest.clone(),
            suite_id: self.suite_id.clone(),
            certification_id: self.certification_id.clone(),
            certification_status: status.into(),
            baseline_status: self.baseline_status.clone(),
            latest_status: self.latest_status.clone(),
            expires_at_ms: self.expires_at_ms,
            admitted,
            refusal: refusal.into(),
        }
    }
}

pub fn missing_gate(namespace: &str, revision_digest: &str) -> AgentPromotionGate {
    AgentPromotionGate {
        namespace: namespace.into(),
        revision_digest: revision_digest.into(),
        suite_id: String::new(),
        certification_id: String::new(),
        certification_status: STATUS_MISSING.into(),
        baseline_status: String::new(),
        latest_status: String::new(),
        expires_at_ms: 0,
        admitted: false,
        refusal: REFUSAL_MISSING.into(),
    }
}

pub fn not_required_gate(namespace: &str, revision_digest: &str) -> AgentPromotionGate {
    AgentPromotionGate {
        namespace: namespace.into(),
        revision_digest: revision_digest.into(),
        suite_id: String::new(),
        certification_id: String::new(),
        certification_status: STATUS_NOT_REQUIRED.into(),
        baseline_status: String::new(),
        latest_status: String::new(),
        expires_at_ms: 0,
        admitted: true,
        refusal: String::new(),
    }
}

pub fn promotion_gate(
    from: &[DefinitionRevisionMember],
    to: &[DefinitionRevisionMember],
    bound: Option<&AgentDefinitionCertification>,
    now_ms: i64,
    namespace: &str,
    revision_digest: &str,
) -> AgentPromotionGate {
    if !agent_members_changed(from, to) {
        return not_required_gate(namespace, revision_digest);
    }
    match bound {
        Some(certification) => certification.gate(now_ms),
        None => missing_gate(namespace, revision_digest),
    }
}

pub fn refuse_direct_agent_publication(
    revision: &crate::sekai::definition_branch::DefinitionRevision,
) -> Result<(), String> {
    if revision.published
        && revision
            .members
            .iter()
            .any(|member| member.member_kind == MEMBER_KIND_AGENT)
    {
        return Err(REFUSAL_MISSING.into());
    }
    Ok(())
}

pub fn require_agent_promotion(
    from: &[DefinitionRevisionMember],
    to: &[DefinitionRevisionMember],
    bound: Option<&AgentDefinitionCertification>,
    now_ms: i64,
) -> Result<(), String> {
    if !agent_members_changed(from, to) {
        return Ok(());
    }
    let Some(certification) = bound else {
        return Err(REFUSAL_MISSING.into());
    };
    let gate = certification.gate(now_ms);
    if gate.admitted {
        Ok(())
    } else {
        Err(gate.refusal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::DefinitionRevisionMember;

    fn member(kind: &str, id: &str, digest: &str) -> DefinitionRevisionMember {
        DefinitionRevisionMember {
            member_kind: kind.into(),
            member_id: id.into(),
            member_digest: digest.into(),
        }
    }

    fn cert(latest: &str, expires: i64, revoked: i64) -> AgentDefinitionCertification {
        AgentDefinitionCertification {
            namespace: "ops".into(),
            revision_digest: "rev".into(),
            suite_id: "suite".into(),
            certification_id: "cert".into(),
            baseline_status: STATUS_PASS.into(),
            latest_status: latest.into(),
            expires_at_ms: expires,
            revoked_at_ms: revoked,
            bound_by: "reviewer".into(),
            bound_at_ms: 1,
        }
    }

    #[test]
    fn non_agent_changes_do_not_require_certification() {
        let from = [member("function", "fn", "a")];
        let to = [member("function", "fn", "b")];
        require_agent_promotion(&from, &to, None, 10).unwrap();
    }

    #[test]
    fn unchanged_agents_do_not_require_certification() {
        let from = [
            member("agent", "triage", "a"),
            member("function", "fn", "b"),
        ];
        let to = [
            member("agent", "triage", "a"),
            member("function", "fn", "c"),
        ];
        require_agent_promotion(&from, &to, None, 10).unwrap();
    }

    #[test]
    fn agent_change_without_certification_is_denied() {
        let from = [member("agent", "triage", "a")];
        let to = [member("agent", "triage", "b")];
        assert_eq!(
            require_agent_promotion(&from, &to, None, 10).unwrap_err(),
            REFUSAL_MISSING
        );
    }

    #[test]
    fn passing_current_certification_admits_an_agent_change() {
        let from = [member("agent", "triage", "a")];
        let to = [member("agent", "triage", "b")];
        let bound = cert(STATUS_PASS, 100, 0);
        require_agent_promotion(&from, &to, Some(&bound), 10).unwrap();
        assert!(bound.gate(10).admitted);
    }

    #[test]
    fn published_agent_seed_is_refused() {
        let draft = crate::sekai::definition_branch::DefinitionRevision {
            contract_version: crate::sekai::definition_branch::REVISION_CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            revision_digest: "rev".into(),
            parent_revision_digest: String::new(),
            members: vec![member("agent", "triage", "a")],
            published: false,
            created_by: "author".into(),
            created_at_ms: 1,
        };
        let mut published = draft.clone();
        published.published = true;
        assert_eq!(
            refuse_direct_agent_publication(&published).unwrap_err(),
            REFUSAL_MISSING
        );
        refuse_direct_agent_publication(&draft).unwrap();
    }

    #[test]
    fn revoked_stale_and_failed_evidence_are_denied() {
        let from = [member("agent", "triage", "a")];
        let to = [member("agent", "triage", "b")];
        assert_eq!(
            require_agent_promotion(&from, &to, Some(&cert(STATUS_PASS, 100, 5)), 10).unwrap_err(),
            REFUSAL_REVOKED
        );
        assert_eq!(
            require_agent_promotion(&from, &to, Some(&cert(STATUS_PASS, 10, 0)), 10).unwrap_err(),
            REFUSAL_STALE
        );
        assert_eq!(
            require_agent_promotion(&from, &to, Some(&cert(STATUS_FAIL, 100, 0)), 10).unwrap_err(),
            REFUSAL_FAILED
        );
    }
}
