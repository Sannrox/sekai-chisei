//! Role and grant records shared by the store and Chisei principal mapping.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Role {
    #[default]
    Viewer,
    Editor,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "editor" => Some(Self::Editor),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
            Self::Admin => "admin",
        }
    }
}

/// Purpose and lifetime for one grant. Empty purpose and `not_after_ms == 0`
/// is the open-ended default (off until a namespace policy requires terms).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantTerm {
    pub purpose: String,
    pub not_after_ms: i64,
    pub exception_reason: String,
}

/// Opt-in per namespace: new grants need a purpose and an end date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceGrantPolicy {
    pub namespace: String,
    pub max_duration_ms: i64,
    pub require_terms: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantTermError {
    MissingPurpose,
    MissingEndDate,
    DurationExceedsMaximum,
    Expired,
}

impl GrantTermError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingPurpose => "grant requires a purpose",
            Self::MissingEndDate => "grant requires an end date",
            Self::DurationExceedsMaximum => "grant duration exceeds the namespace maximum",
            Self::Expired => "grant expired",
        }
    }
}

impl std::fmt::Display for GrantTermError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl GrantTerm {
    pub fn from_grant(grant: &Grant) -> Self {
        Self {
            purpose: grant.purpose.clone(),
            not_after_ms: grant.not_after_ms,
            exception_reason: grant.exception_reason.clone(),
        }
    }

    /// Validate a new or renewed term against an optional namespace policy.
    pub fn prepare(
        self,
        policy: Option<&NamespaceGrantPolicy>,
        now_ms: i64,
    ) -> Result<Self, GrantTermError> {
        let Some(policy) = policy.filter(|policy| policy.require_terms) else {
            return Ok(self);
        };
        if self.purpose.trim().is_empty() {
            return Err(GrantTermError::MissingPurpose);
        }
        if self.not_after_ms == 0 {
            if self.exception_reason.trim().is_empty() {
                return Err(GrantTermError::MissingEndDate);
            }
            return Ok(self);
        }
        if self.not_after_ms <= now_ms {
            return Err(GrantTermError::Expired);
        }
        if policy.max_duration_ms > 0 {
            let duration = self.not_after_ms.saturating_sub(now_ms);
            if duration > policy.max_duration_ms && self.exception_reason.trim().is_empty() {
                return Err(GrantTermError::DurationExceedsMaximum);
            }
        }
        Ok(self)
    }

    pub fn is_active(&self, now_ms: i64) -> Result<(), GrantTermError> {
        if self.not_after_ms != 0 && now_ms >= self.not_after_ms {
            Err(GrantTermError::Expired)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Grant {
    pub id: String,
    pub object_id: String,
    pub principal: String,
    pub role: Role,
    pub created: i64,
    pub purpose: String,
    pub not_after_ms: i64,
    pub exception_reason: String,
}

impl Grant {
    pub fn term(&self) -> GrantTerm {
        GrantTerm::from_grant(self)
    }

    pub fn with_term(mut self, term: GrantTerm) -> Self {
        self.purpose = term.purpose;
        self.not_after_ms = term.not_after_ms;
        self.exception_reason = term.exception_reason;
        self
    }

    pub fn is_active(&self, now_ms: i64) -> Result<(), GrantTermError> {
        self.term().is_active(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> NamespaceGrantPolicy {
        NamespaceGrantPolicy {
            namespace: "ops".into(),
            max_duration_ms: 10_000,
            require_terms: true,
        }
    }

    #[test]
    fn off_by_default_allows_open_ended_grants() {
        let term = GrantTerm::default();
        assert_eq!(term.clone().prepare(None, 1).unwrap(), GrantTerm::default());
        assert!(term.is_active(1_000).is_ok());
    }

    #[test]
    fn required_terms_refuse_a_grant_without_an_end_date() {
        let term = GrantTerm {
            purpose: "audit".into(),
            ..GrantTerm::default()
        };
        assert_eq!(
            term.prepare(Some(&policy()), 1).unwrap_err(),
            GrantTermError::MissingEndDate
        );
    }

    #[test]
    fn required_terms_allow_a_permanent_exception() {
        let term = GrantTerm {
            purpose: "break-glass".into(),
            exception_reason: "incident-9".into(),
            ..GrantTerm::default()
        };
        assert_eq!(term.clone().prepare(Some(&policy()), 1).unwrap(), term);
        assert!(term.is_active(1_000_000).is_ok());
    }

    #[test]
    fn expired_grant_denies_and_renewal_stays_active() {
        let expired = GrantTerm {
            purpose: "audit".into(),
            not_after_ms: 10,
            ..GrantTerm::default()
        };
        assert_eq!(expired.is_active(10).unwrap_err(), GrantTermError::Expired);
        let renewed = GrantTerm {
            purpose: "audit".into(),
            not_after_ms: 50,
            ..GrantTerm::default()
        };
        assert!(
            renewed
                .prepare(Some(&policy()), 20)
                .unwrap()
                .is_active(20)
                .is_ok()
        );
    }
}
