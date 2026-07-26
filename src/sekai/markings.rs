//! Classification markings and purpose constraints (#301).
//!
//! Provisional v1 vocabulary reuses the evidence lattice
//! `public < internal < confidential < restricted`. Markings are optional
//! object properties; purpose constraints are optional action-type fields
//! paired with principal allow-lists.
//!
//! Migration posture:
//! - **Unmarked** objects and actions without `required_purpose` impose no
//!   extra check (fail open for legacy data).
//! - **Marked** objects and purpose-gated actions fail closed when the
//!   principal lacks a sufficient clearance or purpose allow-list entry.

use crate::domain::Object;
use crate::sekai::evidence::EvidenceClassification;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Object property key for an optional access-control marking.
/// Named distinctly from schema property `classification` and free-form
/// domain fields so pre-existing data is not reinterpreted as a security gate.
pub const OBJECT_CLASSIFICATION_PROPERTY: &str = "access_marking";
/// Principal profile property: highest classification the principal may read.
pub const PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY: &str = "classification_ceiling";
/// Principal profile property: comma-separated or JSON array of purposes.
pub const PRINCIPAL_ALLOWED_PURPOSES_PROPERTY: &str = "allowed_purposes";
/// Canonical external_id for a principal profile object.
pub const PRINCIPAL_PROFILE_EXTERNAL_ID_PREFIX: &str = "principal:";
/// Object kind for principal authority profiles (admin-managed only).
pub const PRINCIPAL_PROFILE_KIND: &str = "principal_profile";
/// Property set to `"true"` when a credential admin sealed the profile.
pub const PRINCIPAL_PROFILE_SEALED_PROPERTY: &str = "sealed_by_credential_admin";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalAuthority {
    pub principal: String,
    /// `None` means no explicit clearance was configured.
    pub classification_ceiling: Option<EvidenceClassification>,
    /// Empty means no purpose allow-list is configured.
    pub allowed_purposes: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkingDecision {
    NotApplicable,
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkingCheckResult {
    pub decision: MarkingDecision,
    pub decision_id: String,
    pub object_classification: Option<String>,
    pub principal_ceiling: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeCheckResult {
    pub decision: MarkingDecision,
    pub decision_id: String,
    pub required_purpose: String,
    pub detail: String,
}

/// Build the canonical external id for a principal profile object.
pub fn principal_profile_external_id(principal: &str) -> String {
    format!("{PRINCIPAL_PROFILE_EXTERNAL_ID_PREFIX}{}", principal.trim())
}

/// Parse an optional classification token. Empty → `None`. Invalid → error.
pub fn parse_optional_classification(
    value: &str,
) -> Result<Option<EvidenceClassification>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    parse_classification(trimmed).map(Some)
}

pub fn parse_classification(value: &str) -> Result<EvidenceClassification, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "public" => Ok(EvidenceClassification::Public),
        "internal" => Ok(EvidenceClassification::Internal),
        "confidential" => Ok(EvidenceClassification::Confidential),
        "restricted" => Ok(EvidenceClassification::Restricted),
        other => Err(format!("unknown classification marking: {other}")),
    }
}

/// Extract optional access marking from an object.
///
/// Unknown tokens are ignored (treated as unmarked) so free-form domain values
/// on legacy objects never fail closed or hide data; only the provisional
/// lattice tokens enforce clearance.
pub fn object_classification(object: &Object) -> Result<Option<EvidenceClassification>, String> {
    match object.properties.get(OBJECT_CLASSIFICATION_PROPERTY) {
        None => Ok(None),
        Some(value) => match parse_optional_classification(value) {
            Ok(parsed) => Ok(parsed),
            Err(_) => Ok(None),
        },
    }
}

/// Parse a principal authority snapshot from a principal profile object.
pub fn principal_authority_from_profile(
    principal: &str,
    profile: Option<&Object>,
) -> Result<PrincipalAuthority, String> {
    let Some(profile) = profile else {
        return Ok(PrincipalAuthority {
            principal: principal.into(),
            classification_ceiling: None,
            allowed_purposes: BTreeSet::new(),
        });
    };
    let ceiling = match profile
        .properties
        .get(PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY)
    {
        None => None,
        Some(value) => parse_optional_classification(value)?,
    };
    let purposes = match profile.properties.get(PRINCIPAL_ALLOWED_PURPOSES_PROPERTY) {
        None => BTreeSet::new(),
        Some(raw) => parse_purpose_list(raw)?,
    };
    Ok(PrincipalAuthority {
        principal: principal.into(),
        classification_ceiling: ceiling,
        allowed_purposes: purposes,
    })
}

/// Trusted local service principals receive the top of the lattice and any purpose.
pub fn trusted_service_authority(principal: &str) -> Option<PrincipalAuthority> {
    if matches!(principal, "root" | "local" | "chisei-gateway") {
        Some(PrincipalAuthority {
            principal: principal.into(),
            classification_ceiling: Some(EvidenceClassification::Restricted),
            allowed_purposes: BTreeSet::new(), // empty allow-list is not consulted for trusted
        })
    } else {
        None
    }
}

/// Whether a trusted principal bypasses purpose allow-lists.
pub fn is_trusted_service_principal(principal: &str) -> bool {
    matches!(principal, "root" | "local" | "chisei-gateway")
}

/// Evaluate whether `authority` may read an object with `object_marking`.
///
/// - No object marking → not applicable (fail open).
/// - Trusted service principals → allow.
/// - Marked object + no ceiling configured → deny (fail closed).
/// - Marked object + ceiling < marking → deny.
/// - Otherwise allow.
pub fn evaluate_marking_access(
    operation_id: &str,
    object_marking: Option<EvidenceClassification>,
    authority: &PrincipalAuthority,
) -> MarkingCheckResult {
    // Per-invocation id so repeated allows do not collide in the audit ledger.
    let decision_id = format!(
        "marking:{operation_id}:{}",
        uuid::Uuid::new_v4().as_simple()
    );
    let Some(marking) = object_marking else {
        return MarkingCheckResult {
            decision: MarkingDecision::NotApplicable,
            decision_id,
            object_classification: None,
            principal_ceiling: authority
                .classification_ceiling
                .map(|value| value.as_str().into()),
            detail: "object has no classification marking".into(),
        };
    };
    if is_trusted_service_principal(&authority.principal) {
        return MarkingCheckResult {
            decision: MarkingDecision::Allow,
            decision_id,
            object_classification: Some(marking.as_str().into()),
            principal_ceiling: Some(EvidenceClassification::Restricted.as_str().into()),
            detail: "trusted service principal".into(),
        };
    }
    let Some(ceiling) = authority.classification_ceiling else {
        return MarkingCheckResult {
            decision: MarkingDecision::Deny,
            decision_id,
            object_classification: Some(marking.as_str().into()),
            principal_ceiling: None,
            detail: "principal has no classification_ceiling for a marked object".into(),
        };
    };
    if ceiling >= marking {
        MarkingCheckResult {
            decision: MarkingDecision::Allow,
            decision_id,
            object_classification: Some(marking.as_str().into()),
            principal_ceiling: Some(ceiling.as_str().into()),
            detail: "principal ceiling covers object marking".into(),
        }
    } else {
        MarkingCheckResult {
            decision: MarkingDecision::Deny,
            decision_id,
            object_classification: Some(marking.as_str().into()),
            principal_ceiling: Some(ceiling.as_str().into()),
            detail: "principal classification_ceiling is below object marking".into(),
        }
    }
}

/// Evaluate whether `authority` may invoke an action requiring `required_purpose`.
///
/// - Empty required purpose → not applicable.
/// - Trusted service principals → allow.
/// - Required purpose not in allow-list → deny (fail closed, including empty list).
pub fn evaluate_purpose_access(
    operation_id: &str,
    required_purpose: &str,
    authority: &PrincipalAuthority,
) -> PurposeCheckResult {
    let decision_id = format!(
        "purpose:{operation_id}:{}",
        uuid::Uuid::new_v4().as_simple()
    );
    let required = required_purpose.trim();
    if required.is_empty() {
        return PurposeCheckResult {
            decision: MarkingDecision::NotApplicable,
            decision_id,
            required_purpose: String::new(),
            detail: "action does not require a purpose".into(),
        };
    }
    if is_trusted_service_principal(&authority.principal) {
        return PurposeCheckResult {
            decision: MarkingDecision::Allow,
            decision_id,
            required_purpose: required.into(),
            detail: "trusted service principal".into(),
        };
    }
    if authority.allowed_purposes.contains(required) {
        PurposeCheckResult {
            decision: MarkingDecision::Allow,
            decision_id,
            required_purpose: required.into(),
            detail: "purpose is allow-listed for principal".into(),
        }
    } else {
        PurposeCheckResult {
            decision: MarkingDecision::Deny,
            decision_id,
            required_purpose: required.into(),
            detail: "purpose is not allow-listed for principal".into(),
        }
    }
}

fn parse_purpose_list(raw: &str) -> Result<BTreeSet<String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(BTreeSet::new());
    }
    if trimmed.starts_with('[') {
        let values: Vec<String> =
            serde_json::from_str(trimmed).map_err(|error| format!("allowed_purposes: {error}"))?;
        return Ok(values
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect());
    }
    Ok(trimmed
        .split([',', ';', ' '])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn object_with_marking(marking: &str) -> Object {
        Object {
            id: "obj-1".into(),
            kind: "artifact".into(),
            name: "secret".into(),
            namespace: "ns".into(),
            external_id: "artifact:1".into(),
            properties: HashMap::from([(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into())]),
            created: 1,
            updated: 1,
        }
    }

    fn authority(ceiling: Option<EvidenceClassification>, purposes: &[&str]) -> PrincipalAuthority {
        PrincipalAuthority {
            principal: "alice".into(),
            classification_ceiling: ceiling,
            allowed_purposes: purposes.iter().map(|p| (*p).into()).collect(),
        }
    }

    #[test]
    fn unmarked_object_is_not_applicable() {
        let obj = Object {
            id: "o".into(),
            kind: "x".into(),
            name: "n".into(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        };
        let result = evaluate_marking_access(
            "op1",
            object_classification(&obj).unwrap(),
            &authority(None, &[]),
        );
        assert_eq!(result.decision, MarkingDecision::NotApplicable);
    }

    #[test]
    fn marked_object_denies_without_ceiling() {
        let obj = object_with_marking("confidential");
        let result = evaluate_marking_access(
            "op2",
            object_classification(&obj).unwrap(),
            &authority(None, &[]),
        );
        assert_eq!(result.decision, MarkingDecision::Deny);
    }

    #[test]
    fn marked_object_requires_sufficient_ceiling() {
        let obj = object_with_marking("confidential");
        let deny = evaluate_marking_access(
            "op3",
            object_classification(&obj).unwrap(),
            &authority(Some(EvidenceClassification::Internal), &[]),
        );
        assert_eq!(deny.decision, MarkingDecision::Deny);
        let allow = evaluate_marking_access(
            "op4",
            object_classification(&obj).unwrap(),
            &authority(Some(EvidenceClassification::Confidential), &[]),
        );
        assert_eq!(allow.decision, MarkingDecision::Allow);
    }

    #[test]
    fn purpose_gate_fails_closed() {
        let deny = evaluate_purpose_access("op5", "incident-response", &authority(None, &[]));
        assert_eq!(deny.decision, MarkingDecision::Deny);
        let allow = evaluate_purpose_access(
            "op6",
            "incident-response",
            &authority(None, &["incident-response"]),
        );
        assert_eq!(allow.decision, MarkingDecision::Allow);
        let na = evaluate_purpose_access("op7", "", &authority(None, &[]));
        assert_eq!(na.decision, MarkingDecision::NotApplicable);
    }

    #[test]
    fn trusted_principal_bypasses_gates() {
        let trusted = trusted_service_authority("root").unwrap();
        let marking =
            evaluate_marking_access("op8", Some(EvidenceClassification::Restricted), &trusted);
        assert_eq!(marking.decision, MarkingDecision::Allow);
        let purpose = evaluate_purpose_access("op9", "any-purpose", &trusted);
        assert_eq!(purpose.decision, MarkingDecision::Allow);
    }
}
