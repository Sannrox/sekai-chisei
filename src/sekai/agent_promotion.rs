//! ADR 0079 certification gate for agent-definition promotion (#1353).
//!
//! Merging a proposal that changes an agent-definition member requires a
//! current, non-revoked, baseline-passing certification bound to the
//! candidate revision. Missing, stale, failed, or revoked evidence is deny.
//! Certification is not a runtime grant. Binding copies suite identity and
//! pass/fail from a stored suite result; authors of agent-member changes
//! since the published base cannot self-certify, revocation is one-way, and
//! expiry is capped. Merge does not re-run evaluations.
//!
//! Binding also snapshots the run's mean case score (#1640). When the
//! published revision holds a non-revoked, scored certification on the same
//! suite, a candidate whose mean score falls more than
//! `SEKAI_AGENT_PROMOTION_MAX_REGRESSION_PERCENT` (default 20) below it is
//! refused with `agent_promotion_eval_regression`. No baseline keeps the
//! pass/fail gate unchanged.

use crate::sekai::definition_branch::{DefinitionRevision, DefinitionRevisionMember};

pub const AGENT_PROMOTION_CONTRACT: &str = "sekai.agent-definition-promotion/v1";
pub const MEMBER_KIND_AGENT: &str = "agent";
pub const STATUS_PASS: &str = "pass";
pub const STATUS_FAIL: &str = "fail";
pub const STATUS_MISSING: &str = "missing";
pub const STATUS_STALE: &str = "stale";
pub const STATUS_REVOKED: &str = "revoked";
pub const STATUS_ADMITTED: &str = "admitted";
pub const STATUS_NOT_REQUIRED: &str = "not_required";
pub const STATUS_REGRESSED: &str = "regressed";
pub const REFUSAL_MISSING: &str = "agent_promotion_requires_certification";
pub const REFUSAL_REVOKED: &str = "agent_promotion_certification_revoked";
pub const REFUSAL_STALE: &str = "agent_promotion_certification_stale";
pub const REFUSAL_FAILED: &str = "agent_promotion_certification_failed";
pub const REFUSAL_REGRESSION: &str = "agent_promotion_eval_regression";
pub const REFUSAL_SELF_CERTIFY: &str = "agent_promotion_self_certification_forbidden";
pub const REFUSAL_REVOKE_UNDO: &str = "agent_promotion_certification_revoke_is_final";
pub const REFUSAL_SUITE_MISSING: &str = "agent_promotion_certification_suite_result_missing";
pub const REFUSAL_STATUS_MISMATCH: &str = "agent_promotion_certification_status_mismatch";
pub const REFUSAL_TTL: &str = "agent_promotion_certification_expiry_exceeds_ttl";
pub const MAX_CERTIFICATION_TTL_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const MAX_CERTIFICATION_LINEAGE_WALK: usize = 4_096;
pub const MAX_REGRESSION_PERCENT_ENV: &str = "SEKAI_AGENT_PROMOTION_MAX_REGRESSION_PERCENT";
pub const DEFAULT_MAX_REGRESSION_PERCENT: u32 = 20;

/// Allowed mean-score drop against the published certification, in percent
/// of the published score. Read once from `SEKAI_AGENT_PROMOTION_MAX_REGRESSION_PERCENT`;
/// an unparsable value keeps the default, and values above 100 clamp to 100.
pub fn max_regression_percent() -> u32 {
    static PERCENT: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *PERCENT.get_or_init(|| {
        let Ok(raw) = std::env::var(MAX_REGRESSION_PERCENT_ENV) else {
            return DEFAULT_MAX_REGRESSION_PERCENT;
        };
        match raw.trim().parse::<u32>() {
            Ok(percent) => percent.min(100),
            Err(_) => {
                tracing::warn!(
                    value = %raw,
                    "invalid {MAX_REGRESSION_PERCENT_ENV}; using {DEFAULT_MAX_REGRESSION_PERCENT}"
                );
                DEFAULT_MAX_REGRESSION_PERCENT
            }
        }
    })
}

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
    /// Mean case score of the bound run, times 1000. `None` on rows bound
    /// before #1640; such rows never act as or face a regression baseline.
    pub mean_score_milli: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSuiteResult {
    pub suite_id: String,
    pub certification_id: String,
    pub baseline_status: String,
    pub latest_status: String,
    pub mean_score_milli: Option<i64>,
}

impl StoredSuiteResult {
    pub fn from_run_pass(suite_id: &str, certification_id: &str, passed: bool) -> Self {
        let status = if passed { STATUS_PASS } else { STATUS_FAIL };
        Self {
            suite_id: suite_id.into(),
            certification_id: certification_id.into(),
            baseline_status: status.into(),
            latest_status: status.into(),
            mean_score_milli: None,
        }
    }

    /// Records the run's mean case score; an empty run has no score.
    pub fn with_scores(mut self, scores: impl IntoIterator<Item = i32>) -> Self {
        let (sum, count) = scores
            .into_iter()
            .fold((0_i64, 0_i64), |(sum, count), score| {
                (sum + i64::from(score), count + 1)
            });
        self.mean_score_milli = (count > 0).then(|| sum * 1000 / count);
        self
    }
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
        if self.revoked_at_ms == 0
            && self.expires_at_ms > self.bound_at_ms.saturating_add(MAX_CERTIFICATION_TTL_MS)
        {
            return Err(REFUSAL_TTL.into());
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

impl AgentDefinitionCertification {
    /// `gate`, then refuse when the mean score regressed past
    /// `max_percent` against a usable `baseline` (the published revision's
    /// certification). A revoked, unscored, non-positive, or other-suite
    /// baseline is ignored.
    pub fn gate_against(
        &self,
        baseline: Option<&AgentDefinitionCertification>,
        now_ms: i64,
        max_percent: u32,
    ) -> AgentPromotionGate {
        let mut gate = self.gate(now_ms);
        if gate.admitted && regressed(self, baseline, max_percent) {
            gate.certification_status = STATUS_REGRESSED.into();
            gate.admitted = false;
            gate.refusal = REFUSAL_REGRESSION.into();
        }
        gate
    }
}

fn regressed(
    candidate: &AgentDefinitionCertification,
    baseline: Option<&AgentDefinitionCertification>,
    max_percent: u32,
) -> bool {
    let Some(baseline) = baseline
        .filter(|baseline| baseline.revoked_at_ms == 0 && baseline.suite_id == candidate.suite_id)
    else {
        return false;
    };
    let (Some(candidate_score), Some(baseline_score)) =
        (candidate.mean_score_milli, baseline.mean_score_milli)
    else {
        return false;
    };
    if baseline_score <= 0 {
        return false;
    }
    // candidate < baseline * (100 - max_percent) / 100, in integers.
    i128::from(candidate_score) * 100
        < i128::from(baseline_score) * i128::from(100 - max_percent.min(100))
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
    baseline: Option<&AgentDefinitionCertification>,
    now_ms: i64,
    namespace: &str,
    revision_digest: &str,
) -> AgentPromotionGate {
    if !agent_members_changed(from, to) {
        return not_required_gate(namespace, revision_digest);
    }
    match bound {
        Some(certification) => {
            certification.gate_against(baseline, now_ms, max_regression_percent())
        }
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

pub fn refuse_revoke_undo(
    existing: Option<&AgentDefinitionCertification>,
    requested_revoked_at_ms: i64,
) -> Result<(), String> {
    if existing.is_some_and(|bound| bound.revoked_at_ms > 0) && requested_revoked_at_ms == 0 {
        Err(REFUSAL_REVOKE_UNDO.into())
    } else {
        Ok(())
    }
}

pub fn agent_change_authors(lineage_newest_first: &[DefinitionRevision]) -> Vec<String> {
    let mut authors = Vec::new();
    for pair in lineage_newest_first.windows(2) {
        if agent_members_changed(&pair[1].members, &pair[0].members)
            && !authors.contains(&pair[0].created_by)
        {
            authors.push(pair[0].created_by.clone());
        }
    }
    authors
}

pub fn certification_lineage(
    candidate: &DefinitionRevision,
    published: Option<&DefinitionRevision>,
    mut load_parent: impl FnMut(&str) -> Result<Option<DefinitionRevision>, String>,
) -> Result<Vec<DefinitionRevision>, String> {
    let stop = published
        .map(|revision| revision.revision_digest.as_str())
        .unwrap_or("");
    let mut lineage = vec![candidate.clone()];
    if !stop.is_empty() && candidate.revision_digest == stop {
        return Ok(lineage);
    }
    let mut current = candidate.parent_revision_digest.clone();
    let mut seen = std::collections::BTreeSet::from([candidate.revision_digest.clone()]);
    for _ in 0..MAX_CERTIFICATION_LINEAGE_WALK {
        if current.is_empty() {
            return Ok(lineage);
        }
        if current == stop {
            if let Some(published) = published {
                lineage.push(published.clone());
            }
            return Ok(lineage);
        }
        if !seen.insert(current.clone()) {
            return Err("definition resource unavailable".into());
        }
        let Some(parent) = load_parent(&current)? else {
            return Err("definition resource unavailable".into());
        };
        current = parent.parent_revision_digest.clone();
        lineage.push(parent);
    }
    Err("definition resource unavailable".into())
}

pub fn bind_certification(
    authors: &[String],
    requested: AgentDefinitionCertification,
    existing: Option<&AgentDefinitionCertification>,
    suite: Option<&StoredSuiteResult>,
) -> Result<AgentDefinitionCertification, String> {
    if authors.contains(&requested.bound_by) {
        return Err(REFUSAL_SELF_CERTIFY.into());
    }
    refuse_revoke_undo(existing, requested.revoked_at_ms)?;
    if let Some(bound) = existing
        && bound.revoked_at_ms == 0
        && requested.revoked_at_ms > 0
    {
        let mut revoked = bound.clone();
        revoked.revoked_at_ms = requested.revoked_at_ms;
        revoked.validate()?;
        return Ok(revoked);
    }
    let Some(suite) = suite else {
        return Err(REFUSAL_SUITE_MISSING.into());
    };
    if suite.suite_id != requested.suite_id || suite.certification_id != requested.certification_id
    {
        return Err(REFUSAL_SUITE_MISSING.into());
    }
    if requested.baseline_status != suite.baseline_status
        || requested.latest_status != suite.latest_status
    {
        return Err(REFUSAL_STATUS_MISMATCH.into());
    }
    let mut requested = requested;
    requested.mean_score_milli = suite.mean_score_milli;
    requested.validate()?;
    Ok(requested)
}

pub fn require_agent_promotion(
    from: &[DefinitionRevisionMember],
    to: &[DefinitionRevisionMember],
    bound: Option<&AgentDefinitionCertification>,
    baseline: Option<&AgentDefinitionCertification>,
    now_ms: i64,
) -> Result<(), String> {
    if !agent_members_changed(from, to) {
        return Ok(());
    }
    let Some(certification) = bound else {
        return Err(REFUSAL_MISSING.into());
    };
    let gate = certification.gate_against(baseline, now_ms, max_regression_percent());
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
            mean_score_milli: None,
        }
    }

    #[test]
    fn non_agent_changes_do_not_require_certification() {
        let from = [member("function", "fn", "a")];
        let to = [member("function", "fn", "b")];
        require_agent_promotion(&from, &to, None, None, 10).unwrap();
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
        require_agent_promotion(&from, &to, None, None, 10).unwrap();
    }

    #[test]
    fn agent_change_without_certification_is_denied() {
        let from = [member("agent", "triage", "a")];
        let to = [member("agent", "triage", "b")];
        assert_eq!(
            require_agent_promotion(&from, &to, None, None, 10).unwrap_err(),
            REFUSAL_MISSING
        );
    }

    #[test]
    fn passing_current_certification_admits_an_agent_change() {
        let from = [member("agent", "triage", "a")];
        let to = [member("agent", "triage", "b")];
        let bound = cert(STATUS_PASS, 100, 0);
        require_agent_promotion(&from, &to, Some(&bound), None, 10).unwrap();
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
            require_agent_promotion(&from, &to, Some(&cert(STATUS_PASS, 100, 5)), None, 10)
                .unwrap_err(),
            REFUSAL_REVOKED
        );
        assert_eq!(
            require_agent_promotion(&from, &to, Some(&cert(STATUS_PASS, 10, 0)), None, 10)
                .unwrap_err(),
            REFUSAL_STALE
        );
        assert_eq!(
            require_agent_promotion(&from, &to, Some(&cert(STATUS_FAIL, 100, 0)), None, 10)
                .unwrap_err(),
            REFUSAL_FAILED
        );
    }

    fn bound(revoked: i64) -> AgentDefinitionCertification {
        AgentDefinitionCertification {
            bound_by: "reviewer".into(),
            revoked_at_ms: revoked,
            expires_at_ms: 1_000,
            ..cert(STATUS_PASS, 1_000, revoked)
        }
    }

    fn suite() -> StoredSuiteResult {
        StoredSuiteResult::from_run_pass("suite", "cert", true)
    }

    fn revision(
        created_by: &str,
        digest: &str,
        parent: &str,
        members: Vec<DefinitionRevisionMember>,
    ) -> DefinitionRevision {
        DefinitionRevision {
            contract_version: crate::sekai::definition_branch::REVISION_CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            revision_digest: digest.into(),
            parent_revision_digest: parent.into(),
            members,
            published: false,
            created_by: created_by.into(),
            created_at_ms: 1,
        }
    }

    #[test]
    fn agent_change_authors_ignore_later_unrelated_edits() {
        let published = revision("root", "pub", "", vec![member("function", "fn", "a")]);
        let alice = revision(
            "alice",
            "alice",
            "pub",
            vec![
                member("function", "fn", "a"),
                member("agent", "triage", "b"),
            ],
        );
        let bob = revision(
            "bob",
            "bob",
            "alice",
            vec![
                member("function", "fn", "c"),
                member("agent", "triage", "b"),
            ],
        );
        assert_eq!(
            agent_change_authors(&[bob.clone(), alice.clone(), published.clone()]),
            vec!["alice".to_string()]
        );
        let loaded = certification_lineage(&bob, Some(&published), |digest| {
            Ok(match digest {
                "alice" => Some(alice.clone()),
                "pub" => Some(published.clone()),
                _ => None,
            })
        })
        .unwrap();
        assert_eq!(
            loaded
                .iter()
                .map(|revision| revision.revision_digest.as_str())
                .collect::<Vec<_>>(),
            ["bob", "alice", "pub"]
        );
        assert_eq!(agent_change_authors(&loaded), vec!["alice".to_string()]);
    }

    #[test]
    fn bind_refuses_author_as_certifier() {
        let mut requested = bound(0);
        requested.bound_by = "author".into();
        assert_eq!(
            bind_certification(&["author".into()], requested, None, Some(&suite())).unwrap_err(),
            REFUSAL_SELF_CERTIFY
        );
    }

    #[test]
    fn bind_refuses_overwrite_of_a_non_null_revoke() {
        let existing = bound(4);
        assert_eq!(
            bind_certification(
                &["author".into()],
                bound(0),
                Some(&existing),
                Some(&suite())
            )
            .unwrap_err(),
            REFUSAL_REVOKE_UNDO
        );
        bind_certification(
            &["author".into()],
            bound(4),
            Some(&existing),
            Some(&suite()),
        )
        .unwrap();
    }

    #[test]
    fn bind_requires_statuses_from_a_stored_suite_result() {
        assert_eq!(
            bind_certification(&["author".into()], bound(0), None, None).unwrap_err(),
            REFUSAL_SUITE_MISSING
        );
        let mismatched = AgentDefinitionCertification {
            latest_status: STATUS_FAIL.into(),
            ..bound(0)
        };
        assert_eq!(
            bind_certification(&["author".into()], mismatched, None, Some(&suite())).unwrap_err(),
            REFUSAL_STATUS_MISMATCH
        );
        bind_certification(&["author".into()], bound(0), None, Some(&suite())).unwrap();
    }

    #[test]
    fn bind_refuses_uncapped_expiry() {
        let requested = AgentDefinitionCertification {
            expires_at_ms: i64::MAX,
            ..bound(0)
        };
        assert_eq!(
            bind_certification(&["author".into()], requested, None, Some(&suite())).unwrap_err(),
            REFUSAL_TTL
        );
    }

    #[test]
    fn bind_allows_revoke_of_an_uncapped_existing_cert() {
        let existing = AgentDefinitionCertification {
            expires_at_ms: i64::MAX,
            revoked_at_ms: 0,
            ..bound(0)
        };
        let requested = AgentDefinitionCertification {
            expires_at_ms: i64::MAX,
            revoked_at_ms: 4,
            ..bound(4)
        };
        bind_certification(
            &["author".into()],
            requested,
            Some(&existing),
            Some(&suite()),
        )
        .unwrap();
    }

    #[test]
    fn bind_allows_revoke_without_a_stored_suite_result() {
        let existing = bound(0);
        let requested = bound(4);
        let revoked =
            bind_certification(&["author".into()], requested, Some(&existing), None).unwrap();
        assert_eq!(revoked.revoked_at_ms, 4);
        assert_eq!(revoked.baseline_status, existing.baseline_status);
        assert_eq!(revoked.latest_status, existing.latest_status);
    }

    fn scored(revision: &str, score: Option<i64>) -> AgentDefinitionCertification {
        AgentDefinitionCertification {
            revision_digest: revision.into(),
            mean_score_milli: score,
            ..cert(STATUS_PASS, 100, 0)
        }
    }

    #[test]
    fn regression_within_the_threshold_is_admitted() {
        let baseline = scored("pub", Some(1_000));
        let gate = scored("rev", Some(800)).gate_against(Some(&baseline), 10, 20);
        assert!(gate.admitted);
        assert_eq!(gate.certification_status, STATUS_ADMITTED);
    }

    #[test]
    fn regression_beyond_the_threshold_is_refused() {
        let baseline = scored("pub", Some(1_000));
        let gate = scored("rev", Some(799)).gate_against(Some(&baseline), 10, 20);
        assert!(!gate.admitted);
        assert_eq!(gate.certification_status, STATUS_REGRESSED);
        assert_eq!(gate.refusal, REFUSAL_REGRESSION);
        let from = [member("agent", "triage", "a")];
        let to = [member("agent", "triage", "b")];
        assert_eq!(
            require_agent_promotion(
                &from,
                &to,
                Some(&scored("rev", Some(0))),
                Some(&baseline),
                10
            )
            .unwrap_err(),
            REFUSAL_REGRESSION
        );
    }

    #[test]
    fn missing_or_unusable_baseline_keeps_the_pass_fail_gate() {
        let candidate = scored("rev", Some(0));
        let other_suite = AgentDefinitionCertification {
            suite_id: "other".into(),
            ..scored("pub", Some(1_000))
        };
        for baseline in [
            None,
            Some(scored("pub", None)),
            Some(scored("pub", Some(0))),
            Some(AgentDefinitionCertification {
                revoked_at_ms: 5,
                ..scored("pub", Some(1_000))
            }),
            Some(other_suite),
        ] {
            assert!(candidate.gate_against(baseline.as_ref(), 10, 20).admitted);
        }
        assert!(
            scored("rev", None)
                .gate_against(Some(&scored("pub", Some(1_000))), 10, 20)
                .admitted
        );
    }

    #[test]
    fn bind_snapshots_the_suite_mean_score() {
        let suite = suite().with_scores([1, 2]);
        assert_eq!(suite.mean_score_milli, Some(1_500));
        let bound = bind_certification(&["author".into()], bound(0), None, Some(&suite)).unwrap();
        assert_eq!(bound.mean_score_milli, Some(1_500));
        assert_eq!(
            super::StoredSuiteResult::from_run_pass("s", "c", true)
                .with_scores([])
                .mean_score_milli,
            None
        );
    }
}
