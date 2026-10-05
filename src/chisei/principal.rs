//! Chisei-owned principal context for authorization decisions (ADR 0092).
//!
//! Chisei decides who may read an object, which memory classification an
//! actor may retrieve, and whether markings clear an object, only against the
//! types in this module:
//!
//! - [`PrincipalContext`]: the authenticated principals a request acts as,
//!   derived from the credential subject. Chisei builds it with or without
//!   Sekai.
//! - [`PrincipalGrant`] and [`PrincipalRole`]: grants on one object as Chisei
//!   sees them.
//! - [`MarkingClearance`]: whether classification markings clear an object
//!   for a principal.
//!
//! With Sekai attached, a Sekai-side adapter maps Sekai roles, grants, and
//! classification-lattice results into these types (ADR 0092 rule 5), so the
//! lattice itself is never duplicated here. Without Sekai, grant and clearance
//! reads through the Sekai fact port refuse, and every decision that needs
//! them denies. A Chisei decision never replaces Sekai's own authorization
//! recheck on commit (ADR 0082).

/// Credential subjects that read every object, matching control-plane
/// conventions.
pub const PRIVILEGED_PRINCIPALS: &[&str] = &["root", "local"];

/// A grant role as Chisei sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalRole {
    Viewer,
    Editor,
    Admin,
}

/// One grant on an object as Chisei sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalGrant {
    pub principal: String,
    pub role: PrincipalRole,
}

impl PrincipalGrant {
    pub fn new(principal: impl Into<String>, role: PrincipalRole) -> Self {
        Self {
            principal: principal.into(),
            role,
        }
    }
}

/// Classification-marking outcome for one object and one principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkingClearance {
    /// The object carries no classification marking.
    Unmarked,
    /// The principal's clearance covers the object's marking.
    Cleared,
    /// The marking is above the principal's clearance, or cannot be evaluated.
    Denied,
}

impl MarkingClearance {
    pub fn allows(self) -> bool {
        !matches!(self, Self::Denied)
    }
}

/// The principals one request acts as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalContext {
    /// Never empty; the first entry is the primary principal.
    principals: Vec<String>,
}

impl PrincipalContext {
    /// Context for one authenticated credential subject. The subject stays
    /// opaque: it is compared verbatim, never parsed or trimmed.
    pub fn from_credential(subject: &str) -> Self {
        Self {
            principals: vec![subject.to_string()],
        }
    }

    /// Context for independently authenticated principals, primary first.
    /// `None` when no principal is known; callers must deny.
    pub fn from_principals(principals: Vec<String>) -> Option<Self> {
        (!principals.is_empty()).then_some(Self { principals })
    }

    /// The principal marking clearance is evaluated for.
    pub fn primary(&self) -> &str {
        &self.principals[0]
    }

    pub fn principals(&self) -> &[String] {
        &self.principals
    }

    /// True when any principal is a privileged local subject.
    pub fn is_privileged(&self) -> bool {
        self.principals
            .iter()
            .any(|principal| PRIVILEGED_PRINCIPALS.contains(&principal.as_str()))
    }

    /// True when any grant names one of the principals.
    pub fn holds_grant(&self, grants: &[PrincipalGrant]) -> bool {
        grants
            .iter()
            .any(|grant| self.principals.contains(&grant.principal))
    }

    /// Object read access: privileged subjects always read; an object with no
    /// grants is unrestricted; otherwise a principal must hold a grant.
    pub fn may_read(&self, grants: &[PrincipalGrant]) -> bool {
        self.is_privileged() || grants.is_empty() || self.holds_grant(grants)
    }

    /// Role of the first grant that names one of the principals.
    pub fn role_in(&self, grants: &[PrincipalGrant]) -> Option<PrincipalRole> {
        grants
            .iter()
            .find(|grant| self.principals.contains(&grant.principal))
            .map(|grant| grant.role)
    }

    /// True when a principal holds an admin grant.
    pub fn is_admin_in(&self, grants: &[PrincipalGrant]) -> bool {
        grants.iter().any(|grant| {
            self.principals.contains(&grant.principal) && grant.role == PrincipalRole::Admin
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(entries: &[(&str, PrincipalRole)]) -> Vec<PrincipalGrant> {
        entries
            .iter()
            .map(|(principal, role)| PrincipalGrant::new(*principal, *role))
            .collect()
    }

    #[test]
    fn no_principal_builds_no_context() {
        assert!(PrincipalContext::from_principals(Vec::new()).is_none());
    }

    #[test]
    fn unrestricted_objects_are_readable_and_restricted_ones_need_a_grant() {
        let alice = PrincipalContext::from_credential("alice");
        assert!(alice.may_read(&[]));
        assert!(!alice.may_read(&grants(&[("bob", PrincipalRole::Viewer)])));
        assert!(alice.may_read(&grants(&[
            ("bob", PrincipalRole::Viewer),
            ("alice", PrincipalRole::Viewer),
        ])));
        assert!(!alice.holds_grant(&[]));
    }

    #[test]
    fn privileged_subjects_read_without_holding_a_grant() {
        let restricted = grants(&[("bob", PrincipalRole::Viewer)]);
        for subject in PRIVILEGED_PRINCIPALS {
            let context = PrincipalContext::from_credential(subject);
            assert!(context.is_privileged());
            assert!(context.may_read(&restricted));
            assert!(!context.holds_grant(&restricted));
        }
    }

    #[test]
    fn subjects_are_compared_verbatim() {
        let padded = PrincipalContext::from_credential(" root");
        assert!(!padded.is_privileged());
        assert!(!padded.may_read(&grants(&[("root", PrincipalRole::Admin)])));
    }

    #[test]
    fn role_is_the_first_matching_grant_and_admin_needs_an_admin_grant() {
        let alice = PrincipalContext::from_credential("alice");
        let mixed = grants(&[
            ("bob", PrincipalRole::Admin),
            ("alice", PrincipalRole::Editor),
            ("alice", PrincipalRole::Admin),
        ]);
        assert_eq!(alice.role_in(&mixed), Some(PrincipalRole::Editor));
        assert!(alice.is_admin_in(&mixed));
        assert!(!alice.is_admin_in(&grants(&[("bob", PrincipalRole::Admin)])));
        assert_eq!(alice.role_in(&[]), None);
    }

    #[test]
    fn denied_is_the_only_clearance_that_blocks() {
        assert!(MarkingClearance::Unmarked.allows());
        assert!(MarkingClearance::Cleared.allows());
        assert!(!MarkingClearance::Denied.allows());
    }
}
