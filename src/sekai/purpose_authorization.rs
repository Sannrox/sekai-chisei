//! Actor-bound, scoped, expiring purpose authorizations for governed reads.

use serde::{Deserialize, Serialize};

use crate::sekai::markings::{MarkingDecision, is_trusted_service_principal};

pub const PURPOSE_AUTHORIZATION_VERSION: &str = "sekai.purpose-authorization/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeAuthorization {
    pub contract_version: String,
    pub authorization_id: String,
    pub actor: String,
    pub purpose: String,
    pub namespace: String,
    #[serde(default)]
    pub kind: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub policy_activation_digest: String,
    pub created_by: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub revoked_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeDecision {
    pub decision: MarkingDecision,
    pub decision_id: String,
    pub required_purpose: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurposePresentation {
    pub actor: String,
    pub purpose: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PurposeEvaluation<'a> {
    pub operation_id: &'a str,
    pub required_purpose: Option<&'a str>,
    pub presentation: Option<&'a PurposePresentation>,
    pub authorization: Option<&'a PurposeAuthorization>,
    pub namespace: &'a str,
    pub kind: &'a str,
    pub activation_digest: &'a str,
    pub now_ms: i64,
}

impl PurposeAuthorization {
    pub fn prepare(&self) -> Result<Self, String> {
        if self.contract_version != PURPOSE_AUTHORIZATION_VERSION {
            return Err("unsupported purpose authorization contract".into());
        }
        validate_token("authorization_id", &self.authorization_id)?;
        validate_token("actor", &self.actor)?;
        validate_token("purpose", &self.purpose)?;
        validate_token("namespace", &self.namespace)?;
        if !self.kind.is_empty() {
            validate_token("kind", &self.kind)?;
        }
        validate_token("policy_activation_digest", &self.policy_activation_digest)?;
        validate_token("created_by", &self.created_by)?;
        if self.not_after_ms < self.not_before_ms {
            return Err("purpose authorization window is invalid".into());
        }
        Ok(self.clone())
    }

    pub fn covers(
        &self,
        actor: &str,
        purpose: &str,
        namespace: &str,
        kind: &str,
        activation_digest: &str,
        now_ms: i64,
    ) -> bool {
        self.revoked_at_ms == 0
            && self.actor == actor
            && self.purpose == purpose
            && self.namespace == namespace
            && (self.kind.is_empty() || self.kind == kind)
            && self.policy_activation_digest == activation_digest
            && now_ms >= self.not_before_ms
            && now_ms <= self.not_after_ms
    }
}

pub fn evaluate_required_purpose(request: PurposeEvaluation<'_>) -> PurposeDecision {
    let decision_id = format!(
        "purpose:{}:{}",
        request.operation_id,
        uuid::Uuid::new_v4().as_simple()
    );
    let required = request
        .required_purpose
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(required) = required else {
        return PurposeDecision {
            decision: MarkingDecision::NotApplicable,
            decision_id,
            required_purpose: String::new(),
            detail: "kind does not require a purpose".into(),
        };
    };
    let Some(presentation) = request.presentation else {
        return PurposeDecision {
            decision: MarkingDecision::Deny,
            decision_id,
            required_purpose: required.into(),
            detail: "purpose authorization is missing".into(),
        };
    };
    if is_trusted_service_principal(&presentation.actor) {
        return PurposeDecision {
            decision: MarkingDecision::Allow,
            decision_id,
            required_purpose: required.into(),
            detail: "trusted service principal".into(),
        };
    }
    if presentation.purpose.is_empty() {
        return PurposeDecision {
            decision: MarkingDecision::Deny,
            decision_id,
            required_purpose: required.into(),
            detail: "purpose authorization is missing".into(),
        };
    }
    if presentation.purpose != required {
        return PurposeDecision {
            decision: MarkingDecision::Deny,
            decision_id,
            required_purpose: required.into(),
            detail: "presented purpose is incompatible".into(),
        };
    }
    let Some(authorization) = request.authorization else {
        return PurposeDecision {
            decision: MarkingDecision::Deny,
            decision_id,
            required_purpose: required.into(),
            detail: "purpose authorization is missing".into(),
        };
    };
    if authorization.revoked_at_ms != 0 {
        return deny(&decision_id, required, "purpose authorization is revoked");
    }
    if authorization.actor != presentation.actor {
        return deny(
            &decision_id,
            required,
            "purpose authorization actor does not match",
        );
    }
    if authorization.namespace != request.namespace
        || (!authorization.kind.is_empty() && authorization.kind != request.kind)
    {
        return deny(
            &decision_id,
            required,
            "purpose authorization scope does not match",
        );
    }
    if authorization.policy_activation_digest != request.activation_digest {
        return deny(
            &decision_id,
            required,
            "purpose authorization policy revision does not match",
        );
    }
    if request.now_ms < authorization.not_before_ms || request.now_ms > authorization.not_after_ms {
        return deny(&decision_id, required, "purpose authorization is expired");
    }
    if !authorization.covers(
        &presentation.actor,
        required,
        request.namespace,
        request.kind,
        request.activation_digest,
        request.now_ms,
    ) {
        return deny(
            &decision_id,
            required,
            "purpose authorization does not cover the read",
        );
    }
    PurposeDecision {
        decision: MarkingDecision::Allow,
        decision_id,
        required_purpose: required.into(),
        detail: "purpose authorization covers the read".into(),
    }
}

pub fn purpose_bound_context_digest(
    principal_digest: &str,
    purpose: Option<&str>,
) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"purpose_bound_context");
    hasher.update([0]);
    hasher.update(principal_digest.as_bytes());
    hasher.update([0]);
    hasher.update(purpose.unwrap_or("").as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.:/".contains(character))
    {
        return Err(format!("invalid purpose authorization {label}"));
    }
    Ok(())
}

fn deny(decision_id: &str, required: &str, detail: &str) -> PurposeDecision {
    PurposeDecision {
        decision: MarkingDecision::Deny,
        decision_id: decision_id.into(),
        required_purpose: required.into(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> PurposeAuthorization {
        PurposeAuthorization {
            contract_version: PURPOSE_AUTHORIZATION_VERSION.into(),
            authorization_id: "pa-1".into(),
            actor: "alice".into(),
            purpose: "incident-response".into(),
            namespace: "ops".into(),
            kind: "document".into(),
            not_before_ms: 10,
            not_after_ms: 20,
            policy_activation_digest: "act-1".into(),
            created_by: "root".into(),
            created_at_ms: 10,
            revoked_at_ms: 0,
        }
    }

    fn presentation() -> PurposePresentation {
        PurposePresentation {
            actor: "alice".into(),
            purpose: "incident-response".into(),
        }
    }

    fn eval<'a>(
        required: Option<&'a str>,
        presented: Option<&'a PurposePresentation>,
        authorization: Option<&'a PurposeAuthorization>,
        namespace: &'a str,
        digest: &'a str,
        now_ms: i64,
    ) -> PurposeEvaluation<'a> {
        PurposeEvaluation {
            operation_id: "read",
            required_purpose: required,
            presentation: presented,
            authorization,
            namespace,
            kind: "document",
            activation_digest: digest,
            now_ms,
        }
    }

    #[test]
    fn missing_incompatible_expired_actor_revision_and_scope_fail_closed() {
        let authorization = auth();
        let presented = presentation();
        assert_eq!(
            evaluate_required_purpose(eval(
                None,
                Some(&presented),
                Some(&authorization),
                "ops",
                "act-1",
                15,
            ))
            .decision,
            MarkingDecision::NotApplicable
        );
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                None,
                None,
                "ops",
                "act-1",
                15,
            ))
            .decision,
            MarkingDecision::Deny
        );
        let mut wrong_purpose = presented.clone();
        wrong_purpose.purpose = "analytics".into();
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                Some(&wrong_purpose),
                Some(&authorization),
                "ops",
                "act-1",
                15,
            ))
            .detail,
            "presented purpose is incompatible"
        );
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                Some(&presented),
                Some(&authorization),
                "ops",
                "act-1",
                21,
            ))
            .detail,
            "purpose authorization is expired"
        );
        let mut other_actor = presented.clone();
        other_actor.actor = "bob".into();
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                Some(&other_actor),
                Some(&authorization),
                "ops",
                "act-1",
                15,
            ))
            .detail,
            "purpose authorization actor does not match"
        );
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                Some(&presented),
                Some(&authorization),
                "ops",
                "act-2",
                15,
            ))
            .detail,
            "purpose authorization policy revision does not match"
        );
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                Some(&presented),
                Some(&authorization),
                "other",
                "act-1",
                15,
            ))
            .detail,
            "purpose authorization scope does not match"
        );
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                Some(&presented),
                Some(&authorization),
                "ops",
                "act-1",
                15,
            ))
            .decision,
            MarkingDecision::Allow
        );
        let trusted = PurposePresentation {
            actor: "root".into(),
            purpose: String::new(),
        };
        assert_eq!(
            evaluate_required_purpose(eval(
                Some("incident-response"),
                Some(&trusted),
                None,
                "ops",
                "act-1",
                15,
            ))
            .detail,
            "trusted service principal"
        );
        let alice = purpose_bound_context_digest("ctx", Some("incident-response")).unwrap();
        let other = purpose_bound_context_digest("ctx", Some("analytics")).unwrap();
        let empty = purpose_bound_context_digest("ctx", None).unwrap();
        assert_ne!(alice, other);
        assert_ne!(alice, empty);
        let mut unknown = authorization;
        unknown.contract_version = "sekai.purpose-authorization/v2".into();
        assert_eq!(
            unknown.prepare().unwrap_err(),
            "unsupported purpose authorization contract"
        );
    }
}
