//! Bounded, versioned object-instance read authorization policy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::is_valid_property_key;

pub const OBJECT_SECURITY_POLICY_VERSION: &str = "sekai.object-security-policy/v1";
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 64;
const MAX_PREDICATES: usize = 16;
const MAX_VALUE_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectSecurityOperation {
    Read,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectSecurityPredicate {
    AllowAll,
    SubjectEqualsProperty { property: String },
    RequiredScopeEquals { value: String },
    PropertyEquals { property: String, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSecurityRule {
    pub operation: ObjectSecurityOperation,
    pub predicates: Vec<ObjectSecurityPredicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSecurityPolicy {
    pub contract_version: String,
    pub namespace: String,
    pub kind: String,
    pub rules: Vec<ObjectSecurityRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityPolicyRevision {
    pub namespace: String,
    pub kind: String,
    pub revision_digest: String,
    pub canonical_policy_json: Vec<u8>,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityActivation {
    pub namespace: String,
    pub activation_id: String,
    pub policies: BTreeMap<String, String>,
    pub activated_by: String,
    pub activated_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrincipalPolicyContext {
    pub subjects: Vec<String>,
    pub scopes: Vec<String>,
}

impl PrincipalPolicyContext {
    pub fn normalized(mut self) -> Self {
        self.subjects = self
            .subjects
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty() && value != "anonymous")
            .collect();
        self.scopes = self
            .scopes
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect();
        self.subjects.sort();
        self.subjects.dedup();
        self.scopes.sort();
        self.scopes.dedup();
        self
    }

    pub fn digest(&self) -> String {
        let context = self.clone().normalized();
        let mut hasher = Sha256::new();
        hasher.update(b"sekai.object-security-principal/v1\0");
        hasher.update(serde_json::to_vec(&context.subjects).unwrap_or_default());
        hasher.update([0]);
        hasher.update(serde_json::to_vec(&context.scopes).unwrap_or_default());
        format!("{:x}", hasher.finalize())
    }
}

pub const OBJECT_LIST_PAGE_TOKEN_TTL_MS: i64 = 15 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectListPageToken {
    pub principal_digest: String,
    pub namespace: String,
    pub policy_revision: String,
    pub query_digest: String,
    pub offset: i32,
    pub expiry_ms: i64,
}

impl ObjectListPageToken {
    pub fn encode(&self) -> Result<String, String> {
        let json = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            json,
        ))
    }

    pub fn decode(token: &str) -> Result<Self, String> {
        let json = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            token.trim(),
        )
        .map_err(|_| "object_security_cursor_invalid: malformed page token".to_string())?;
        serde_json::from_slice(&json)
            .map_err(|_| "object_security_cursor_invalid: malformed page token".into())
    }

    pub fn validate(
        &self,
        context: &PrincipalPolicyContext,
        namespace: &str,
        policy_revision: &str,
        query_digest: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        if self.expiry_ms <= now_ms {
            return Err("object_security_cursor_expired: page token expired".into());
        }
        if self.principal_digest != context.digest()
            || self.namespace != namespace
            || self.policy_revision != policy_revision
            || self.query_digest != query_digest
            || self.offset < 0
        {
            return Err(
                "object_security_cursor_mismatch: page token is bound to a different authority or query"
                    .into(),
            );
        }
        Ok(())
    }
}

pub fn list_query_digest(filter: &crate::domain::ListFilter) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.object-security-list-query/v1\0");
    hasher.update(filter.kind.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(filter.name.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(filter.namespace.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(filter.order_by.as_bytes());
    hasher.update([0]);
    hasher.update([u8::from(filter.descending)]);
    hasher.update(filter.limit.to_le_bytes());
    for property in &filter.property_filters {
        hasher.update([0]);
        hasher.update(property.key.as_bytes());
        hasher.update([0]);
        hasher.update(property.op.as_bytes());
        hasher.update([0]);
        hasher.update(property.value.as_bytes());
    }
    for interface in &filter.interface_filter {
        hasher.update([0]);
        hasher.update(interface.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

impl ObjectSecurityPolicy {
    pub fn from_canonical_input(input: &[u8]) -> Result<Self, String> {
        if input.is_empty() || input.len() > MAX_POLICY_BYTES {
            return Err(format!(
                "policy JSON must contain 1..={MAX_POLICY_BYTES} bytes"
            ));
        }
        let text = std::str::from_utf8(input)
            .map_err(|error| format!("invalid object-security policy JSON: {error}"))?;
        if crate::sekai::json::contains_duplicate_object_keys(text)
            .map_err(|error| format!("invalid object-security policy JSON: {error}"))?
        {
            return Err(
                "object-security policy JSON must not contain duplicate object keys".into(),
            );
        }
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|error| format!("invalid object-security policy JSON: {error}"))?;
        validate_json_shape(&value)?;
        serde_json::from_value::<Self>(value)
            .map_err(|error| format!("invalid object-security policy JSON: {error}"))?
            .prepare()
    }

    pub fn prepare(mut self) -> Result<Self, String> {
        if self.contract_version != OBJECT_SECURITY_POLICY_VERSION {
            return Err("unsupported object-security policy contract version".into());
        }
        validate_identity("namespace", &self.namespace)?;
        validate_identity("kind", &self.kind)?;
        if self.rules.is_empty() || self.rules.len() > MAX_RULES {
            return Err(format!("policy must contain 1..={MAX_RULES} rules"));
        }
        for rule in &mut self.rules {
            if rule.predicates.is_empty() || rule.predicates.len() > MAX_PREDICATES {
                return Err(format!("rule must contain 1..={MAX_PREDICATES} predicates"));
            }
            for predicate in &rule.predicates {
                predicate.validate()?;
            }
            if rule
                .predicates
                .iter()
                .any(|predicate| matches!(predicate, ObjectSecurityPredicate::AllowAll))
                && rule.predicates.len() != 1
            {
                return Err("allow_all must be the rule's only predicate".into());
            }
            rule.predicates.sort_by_key(predicate_key);
            rule.predicates.dedup();
        }
        self.rules.sort_by_key(rule_key);
        self.rules.dedup();
        Ok(self)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&self.clone().prepare()?).map_err(|error| error.to_string())
    }

    pub fn revision_digest(&self) -> Result<String, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"sekai.object-security-policy/v1\0");
        hasher.update(self.canonical_bytes()?);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

fn validate_json_shape(value: &serde_json::Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "object-security policy must be a JSON object".to_string())?;
    reject_unknown_keys(object, &["contract_version", "namespace", "kind", "rules"])?;
    let rules = object
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "object-security policy rules must be an array".to_string())?;
    for rule in rules {
        let rule = rule
            .as_object()
            .ok_or_else(|| "object-security rule must be an object".to_string())?;
        reject_unknown_keys(rule, &["operation", "predicates"])?;
        let predicates = rule
            .get("predicates")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "object-security predicates must be an array".to_string())?;
        for predicate in predicates {
            let predicate = predicate
                .as_object()
                .ok_or_else(|| "object-security predicate must be an object".to_string())?;
            let kind = predicate
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "object-security predicate kind required".to_string())?;
            let allowed = match kind {
                "allow_all" => &["kind"][..],
                "subject_equals_property" => &["kind", "property"][..],
                "required_scope_equals" => &["kind", "value"][..],
                "property_equals" => &["kind", "property", "value"][..],
                _ => return Err("unsupported object-security predicate".into()),
            };
            reject_unknown_keys(predicate, allowed)?;
        }
    }
    Ok(())
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
) -> Result<(), String> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unknown object-security policy attribute".into());
    }
    Ok(())
}

impl ObjectSecurityPredicate {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::AllowAll => Ok(()),
            Self::SubjectEqualsProperty { property } => validate_property(property),
            Self::RequiredScopeEquals { value } => validate_value("scope", value),
            Self::PropertyEquals { property, value } => {
                validate_property(property)?;
                validate_value("property value", value)
            }
        }
    }
}

fn predicate_key(predicate: &ObjectSecurityPredicate) -> String {
    serde_json::to_string(predicate).unwrap_or_default()
}

fn rule_key(rule: &ObjectSecurityRule) -> String {
    serde_json::to_string(rule).unwrap_or_default()
}

fn validate_identity(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.:/".contains(character))
    {
        return Err(format!("invalid object-security policy {label}"));
    }
    Ok(())
}

fn validate_property(property: &str) -> Result<(), String> {
    if !is_valid_property_key(property) {
        return Err("invalid object-security property key".into());
    }
    Ok(())
}

fn validate_value(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_VALUE_BYTES {
        return Err(format!("{label} must contain 1..={MAX_VALUE_BYTES} bytes"));
    }
    if value.contains('\0') {
        return Err(format!("{label} must not contain NUL"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(rules: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "contract_version": OBJECT_SECURITY_POLICY_VERSION,
            "namespace": "acme",
            "kind": "document",
            "rules": rules
        }))
        .unwrap()
    }

    #[test]
    fn canonicalization_and_digest_are_stable() {
        let left = ObjectSecurityPolicy::from_canonical_input(&document(serde_json::json!([
            {"operation":"read","predicates":[
                {"kind":"property_equals","property":"state","value":"open"},
                {"kind":"required_scope_equals","value":"documents:read"}
            ]},
            {"operation":"read","predicates":[{"kind":"allow_all"}]}
        ])))
        .unwrap();
        let right = ObjectSecurityPolicy::from_canonical_input(&document(serde_json::json!([
            {"operation":"read","predicates":[{"kind":"allow_all"}]},
            {"operation":"read","predicates":[
                {"kind":"required_scope_equals","value":"documents:read"},
                {"kind":"property_equals","property":"state","value":"open"}
            ]}
        ])))
        .unwrap();
        assert_eq!(
            left.canonical_bytes().unwrap(),
            right.canonical_bytes().unwrap()
        );
        assert_eq!(
            left.revision_digest().unwrap(),
            right.revision_digest().unwrap()
        );
    }

    #[test]
    fn duplicate_object_keys_fail_closed() {
        let input = br#"{"contract_version":"sekai.object-security-policy/v1","namespace":"acme","kind":"document","rules":[{"operation":"read","predicates":[{"kind":"allow_all"}]}],"rules":[{"operation":"read","predicates":[{"kind":"property_equals","property":"state","value":"open"}]}]}"#;
        assert!(ObjectSecurityPolicy::from_canonical_input(input).is_err());
    }

    #[test]
    fn unknown_operation_predicate_and_attribute_fail_closed() {
        for rules in [
            serde_json::json!([{"operation":"write","predicates":[{"kind":"allow_all"}]}]),
            serde_json::json!([{"operation":"read","predicates":[{"kind":"header_equals","value":"x"}]}]),
            serde_json::json!([{"operation":"read","predicates":[{"kind":"allow_all","extra":true}]}]),
        ] {
            assert!(ObjectSecurityPolicy::from_canonical_input(&document(rules)).is_err());
        }
    }

    #[test]
    fn property_keys_use_shared_validation() {
        let input = document(serde_json::json!([{
            "operation":"read",
            "predicates":[{"kind":"subject_equals_property","property":"owner.email"}]
        }]));
        assert!(ObjectSecurityPolicy::from_canonical_input(&input).is_err());
    }

    #[test]
    fn postgres_incompatible_nul_values_fail_validation() {
        for predicate in [
            serde_json::json!({"kind":"required_scope_equals","value":"documents:\u{0000}read"}),
            serde_json::json!({"kind":"property_equals","property":"state","value":"open\u{0000}closed"}),
        ] {
            let input = document(serde_json::json!([{
                "operation":"read",
                "predicates":[predicate]
            }]));
            assert!(ObjectSecurityPolicy::from_canonical_input(&input).is_err());
        }
    }

    #[test]
    fn principal_context_discards_empty_and_anonymous_subjects() {
        let context = PrincipalPolicyContext {
            subjects: vec![
                String::new(),
                "  ".into(),
                "anonymous".into(),
                " alice ".into(),
                "alice".into(),
            ],
            scopes: vec![" ".into(), " documents:read ".into()],
        }
        .normalized();
        assert_eq!(context.subjects, ["alice"]);
        assert_eq!(context.scopes, ["documents:read"]);
    }

    #[test]
    fn page_token_rejects_changed_authority_or_expiry() {
        let context = PrincipalPolicyContext {
            subjects: vec!["alice".into()],
            scopes: vec!["documents:read".into()],
        }
        .normalized();
        let token = ObjectListPageToken {
            principal_digest: context.digest(),
            namespace: "acme".into(),
            policy_revision: "rev".into(),
            query_digest: "query".into(),
            offset: 2,
            expiry_ms: 100,
        };
        assert!(token.validate(&context, "acme", "rev", "query", 99).is_ok());
        assert!(
            token
                .validate(&context, "acme", "rev", "query", 100)
                .unwrap_err()
                .contains("expired")
        );
        let other = PrincipalPolicyContext {
            subjects: vec!["bob".into()],
            scopes: vec!["documents:read".into()],
        }
        .normalized();
        assert!(
            token
                .validate(&other, "acme", "rev", "query", 99)
                .unwrap_err()
                .contains("mismatch")
        );
    }
}
