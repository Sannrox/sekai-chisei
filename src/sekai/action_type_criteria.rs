//! Closed Action-type submission criteria (#883 / ADR 0077).
//!
//! Predicates reuse the shipped object-security v1 vocabulary. A criterion
//! that names a hidden or ungranted property fails closed as unavailable and
//! must not leak the property or criterion identity.

use crate::domain::Object;
use crate::sekai::object_security::{
    ObjectSecurityPolicy, ObjectSecurityPredicate, PrincipalPolicyContext, PropertyGrantAccess,
};
use serde::{Deserialize, Serialize};

pub const CRITERION_KIND_ALLOW_ALL: &str = "allow_all";
pub const CRITERION_KIND_SUBJECT_EQUALS_PROPERTY: &str = "subject_equals_property";
pub const CRITERION_KIND_REQUIRED_SCOPE_EQUALS: &str = "required_scope_equals";
pub const CRITERION_KIND_PROPERTY_EQUALS: &str = "property_equals";
pub const CRITERION_UNAVAILABLE: &str = "unavailable";

const RESERVED_CRITERION_IDS: &[&str] = &[
    "allow",
    "budget_exceeded",
    "denied",
    "deny",
    "invalid",
    "require_approval",
    "stale",
    "unavailable",
    "valid",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSubmissionCriterion {
    pub criterion_id: String,
    pub kind: String,
    #[serde(default)]
    pub property: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CriterionDecision {
    Pass,
    Fail { criterion_id: String },
    Unavailable,
}

impl ActionSubmissionCriterion {
    pub fn validate(&self) -> Result<(), String> {
        let criterion_id = self.criterion_id.trim();
        if criterion_id.is_empty() {
            return Err("criterion_id required".into());
        }
        if criterion_id.chars().any(char::is_whitespace) {
            return Err("criterion_id must not contain whitespace".into());
        }
        if RESERVED_CRITERION_IDS.contains(&criterion_id) {
            return Err(format!("criterion_id {criterion_id:?} is reserved"));
        }
        if self.criterion_id != criterion_id {
            return Err("criterion_id must not include surrounding whitespace".into());
        }
        let predicate = self.predicate()?;
        predicate.validate()?;
        Ok(())
    }

    pub fn predicate(&self) -> Result<ObjectSecurityPredicate, String> {
        match self.kind.trim() {
            CRITERION_KIND_ALLOW_ALL => {
                reject_unused_fields(self, false, false)?;
                Ok(ObjectSecurityPredicate::AllowAll)
            }
            CRITERION_KIND_SUBJECT_EQUALS_PROPERTY => {
                reject_unused_fields(self, true, false)?;
                Ok(ObjectSecurityPredicate::SubjectEqualsProperty {
                    property: self.property.clone(),
                })
            }
            CRITERION_KIND_REQUIRED_SCOPE_EQUALS => {
                reject_unused_fields(self, false, true)?;
                Ok(ObjectSecurityPredicate::RequiredScopeEquals {
                    value: self.value.clone(),
                })
            }
            CRITERION_KIND_PROPERTY_EQUALS => {
                reject_unused_fields(self, true, true)?;
                Ok(ObjectSecurityPredicate::PropertyEquals {
                    property: self.property.clone(),
                    value: self.value.clone(),
                })
            }
            other => Err(format!(
                "unknown criterion kind {other:?}; allowed: {CRITERION_KIND_ALLOW_ALL}, {CRITERION_KIND_SUBJECT_EQUALS_PROPERTY}, {CRITERION_KIND_REQUIRED_SCOPE_EQUALS}, {CRITERION_KIND_PROPERTY_EQUALS}"
            )),
        }
    }

    pub fn requires_object(&self) -> Result<bool, String> {
        Ok(matches!(
            self.predicate()?,
            ObjectSecurityPredicate::SubjectEqualsProperty { .. }
                | ObjectSecurityPredicate::PropertyEquals { .. }
        ))
    }

    fn named_property(&self) -> Option<&str> {
        let property = self.property.trim();
        if property.is_empty() {
            None
        } else {
            Some(property)
        }
    }
}

fn reject_unused_fields(
    criterion: &ActionSubmissionCriterion,
    needs_property: bool,
    needs_value: bool,
) -> Result<(), String> {
    if needs_property {
        if criterion.property.trim().is_empty() {
            return Err("criterion property required".into());
        }
    } else if !criterion.property.trim().is_empty() {
        return Err("criterion property is not used by this kind".into());
    }
    if needs_value {
        if criterion.value.trim().is_empty() {
            return Err("criterion value required".into());
        }
    } else if !criterion.value.trim().is_empty() {
        return Err("criterion value is not used by this kind".into());
    }
    Ok(())
}

pub fn validate_submission_criteria(
    criteria: &[ActionSubmissionCriterion],
    object_kind: &str,
    object_mutation: &str,
) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for criterion in criteria {
        criterion.validate()?;
        if !seen.insert(criterion.criterion_id.clone()) {
            return Err(format!(
                "duplicate criterion_id {:?}",
                criterion.criterion_id
            ));
        }
        if criterion.requires_object()? {
            if object_kind.trim().is_empty() {
                return Err(
                    "object-property criteria require object_kind and object_mutation".into(),
                );
            }
            if object_mutation.trim() != "update" {
                return Err("object-property criteria require object_mutation update".into());
            }
        }
    }
    Ok(())
}

pub fn invoker_context(
    actor: &str,
    context: Option<&PrincipalPolicyContext>,
) -> PrincipalPolicyContext {
    let mut context = context.cloned().unwrap_or_default();
    if context
        .subjects
        .iter()
        .all(|subject| subject.trim().is_empty())
    {
        context.subjects = vec![actor.to_string()];
    }
    context.normalized()
}

pub fn evaluate_submission_criteria(
    criteria: &[ActionSubmissionCriterion],
    object: Option<&Object>,
    policy: Option<&ObjectSecurityPolicy>,
    invoker: &PrincipalPolicyContext,
) -> CriterionDecision {
    let invoker = invoker.clone().normalized();
    for criterion in criteria {
        match evaluate_one(criterion, object, policy, &invoker) {
            CriterionDecision::Pass => {}
            other => return other,
        }
    }
    CriterionDecision::Pass
}

fn evaluate_one(
    criterion: &ActionSubmissionCriterion,
    object: Option<&Object>,
    policy: Option<&ObjectSecurityPolicy>,
    invoker: &PrincipalPolicyContext,
) -> CriterionDecision {
    let Ok(predicate) = criterion.predicate() else {
        return CriterionDecision::Unavailable;
    };
    if let Some(property) = criterion.named_property()
        && property_is_hidden(policy, object, property)
    {
        return CriterionDecision::Unavailable;
    }
    let Some(object) = object else {
        return if matches!(
            predicate,
            ObjectSecurityPredicate::AllowAll | ObjectSecurityPredicate::RequiredScopeEquals { .. }
        ) {
            if predicate.matches(invoker, &empty_object()) {
                CriterionDecision::Pass
            } else {
                CriterionDecision::Fail {
                    criterion_id: criterion.criterion_id.clone(),
                }
            }
        } else {
            CriterionDecision::Unavailable
        };
    };
    if predicate.matches(invoker, object) {
        CriterionDecision::Pass
    } else {
        CriterionDecision::Fail {
            criterion_id: criterion.criterion_id.clone(),
        }
    }
}

fn property_is_hidden(
    policy: Option<&ObjectSecurityPolicy>,
    object: Option<&Object>,
    property: &str,
) -> bool {
    let Some(policy) = policy else {
        return false;
    };
    if policy.property_grants_enforced()
        && !policy.allows_property_access(property, PropertyGrantAccess::Read)
    {
        return true;
    }
    if let Some(object) = object
        && policy.value_instance_grants_enforced()
        && let Some(value) = object.properties.get(property)
        && !policy.allows_value_instance_access(
            &object.id,
            property,
            value,
            PropertyGrantAccess::Read,
        )
    {
        return true;
    }
    false
}

fn empty_object() -> Object {
    Object {
        id: String::new(),
        kind: String::new(),
        name: String::new(),
        namespace: String::new(),
        external_id: String::new(),
        properties: std::collections::HashMap::new(),
        created: 0,
        updated: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::object_security::{
        OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityRule, PropertyGrant,
    };

    fn criterion(id: &str, kind: &str, property: &str, value: &str) -> ActionSubmissionCriterion {
        ActionSubmissionCriterion {
            criterion_id: id.into(),
            kind: kind.into(),
            property: property.into(),
            value: value.into(),
        }
    }

    fn object_with(property: &str, value: &str) -> Object {
        let mut object = empty_object();
        object.id = "cust-1".into();
        object.kind = "customer_record".into();
        object.namespace = "acme".into();
        object.properties.insert(property.into(), value.into());
        object
    }

    fn grants(readable: &[&str]) -> ObjectSecurityPolicy {
        ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "customer_record".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(
                readable
                    .iter()
                    .map(|property| PropertyGrant {
                        property: (*property).into(),
                        access: PropertyGrantAccess::Read,
                    })
                    .collect(),
            ),
            value_instance_grants: None,
            required_purpose: None,
        }
    }

    #[test]
    fn names_the_first_failing_visible_criterion() {
        let ready = criterion(
            "ready_for_review",
            CRITERION_KIND_PROPERTY_EQUALS,
            "state",
            "ready",
        );
        let decision = evaluate_submission_criteria(
            &[ready],
            Some(&object_with("state", "draft")),
            None,
            &PrincipalPolicyContext::default(),
        );
        assert_eq!(
            decision,
            CriterionDecision::Fail {
                criterion_id: "ready_for_review".into()
            }
        );
    }

    #[test]
    fn hidden_property_is_unavailable_without_names() {
        let secret = criterion(
            "has_clearance",
            CRITERION_KIND_PROPERTY_EQUALS,
            "secret",
            "yes",
        );
        let decision = evaluate_submission_criteria(
            &[secret],
            Some(&object_with("secret", "no")),
            Some(&grants(&["state"])),
            &PrincipalPolicyContext::default(),
        );
        assert_eq!(decision, CriterionDecision::Unavailable);
        assert!(!format!("{decision:?}").contains("secret"));
    }

    #[test]
    fn invoker_scope_can_pass_without_an_object() {
        let scoped = criterion(
            "operator_scope",
            CRITERION_KIND_REQUIRED_SCOPE_EQUALS,
            "",
            "action.operator",
        );
        let invoker = PrincipalPolicyContext {
            subjects: vec!["alice".into()],
            scopes: vec!["action.operator".into()],
        };
        assert_eq!(
            evaluate_submission_criteria(&[scoped], None, None, &invoker),
            CriterionDecision::Pass
        );
    }

    #[test]
    fn rejects_reserved_and_objectless_property_criteria() {
        let reserved = criterion("unavailable", CRITERION_KIND_ALLOW_ALL, "", "");
        assert!(reserved.validate().unwrap_err().contains("reserved"));
        let property = criterion(
            "ready_for_review",
            CRITERION_KIND_PROPERTY_EQUALS,
            "state",
            "ready",
        );
        let error = validate_submission_criteria(&[property], "", "").unwrap_err();
        assert!(error.contains("object_kind"), "{error}");
    }
}
