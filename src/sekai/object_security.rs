//! Bounded, versioned object-instance authorization policy.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::{ListFilter, Object, is_valid_property_key};

pub const OBJECT_SECURITY_POLICY_VERSION: &str = "sekai.object-security-policy/v1";
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const OBJECT_QUERY_CURSOR_TTL_MS: i64 = 5 * 60 * 1_000;
const MAX_RULES: usize = 64;
const MAX_PREDICATES: usize = 16;
const MAX_PROPERTY_GRANTS: usize = 128;
const MAX_VALUE_BYTES: usize = 1024;
const OBJECT_QUERY_CURSOR_VERSION: &str = "sekai.object-query-cursor/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectSecurityOperation {
    Read,
    Query,
    Traverse,
    Create,
    Update,
    Delete,
    Action,
    Export,
    Sync,
}

impl ObjectSecurityOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Query => "query",
            Self::Traverse => "traverse",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Action => "action",
            Self::Export => "export",
            Self::Sync => "sync",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read" => Ok(Self::Read),
            "query" => Ok(Self::Query),
            "traverse" => Ok(Self::Traverse),
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "action" => Ok(Self::Action),
            "export" => Ok(Self::Export),
            "sync" => Ok(Self::Sync),
            _ => Err("unsupported object-security operation".into()),
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropertyGrantAccess {
    Read,
    Write,
}

impl PropertyGrantAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            _ => Err("unsupported object-security property grant access".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyGrant {
    pub property: String,
    pub access: PropertyGrantAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSecurityPolicy {
    pub contract_version: String,
    pub namespace: String,
    pub kind: String,
    pub rules: Vec<ObjectSecurityRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property_grants: Option<Vec<PropertyGrant>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_purpose: Option<String>,
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

    pub fn digest(&self) -> Result<String, String> {
        let normalized = self.clone().normalized();
        canonical_hex_digest(
            "principal_policy_context",
            &(normalized.subjects, normalized.scopes),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectQueryCursor {
    pub contract_version: String,
    pub offset: i32,
    pub principal_context_digest: String,
    pub namespace: String,
    pub policy_activation_digest: String,
    pub query_digest: String,
    pub expires_at_ms: i64,
}

impl ObjectQueryCursor {
    pub fn issue(
        offset: i32,
        principal_context_digest: String,
        namespace: String,
        policy_activation_digest: String,
        query_digest: String,
        now_ms: i64,
    ) -> Result<Self, String> {
        if offset < 0 || now_ms <= 0 {
            return Err("object query cursor position or issuance time is invalid".into());
        }
        validate_hex_digest("principal_context_digest", &principal_context_digest)?;
        validate_identity("namespace", &namespace)?;
        validate_digest_or_legacy("policy_activation_digest", &policy_activation_digest)?;
        validate_hex_digest("query_digest", &query_digest)?;
        Ok(Self {
            contract_version: OBJECT_QUERY_CURSOR_VERSION.into(),
            offset,
            principal_context_digest,
            namespace,
            policy_activation_digest,
            query_digest,
            expires_at_ms: now_ms.saturating_add(OBJECT_QUERY_CURSOR_TTL_MS),
        })
    }

    pub fn encode(&self, signing_key: &[u8]) -> Result<String, String> {
        self.validate(self.expires_at_ms.saturating_sub(1))?;
        let payload = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)
            .map_err(|_| "invalid cursor signing key")?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    pub fn decode(token: &str, signing_key: &[u8], now_ms: i64) -> Result<Self, String> {
        if token.len() > 8_192 {
            return Err("object query cursor exceeds the supported size".into());
        }
        let (payload, signature) = token
            .split_once('.')
            .ok_or_else(|| "object query cursor is malformed".to_string())?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "object query cursor is malformed".to_string())?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| "object query cursor is malformed".to_string())?;
        let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)
            .map_err(|_| "invalid cursor signing key")?;
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| "object query cursor signature is invalid".to_string())?;
        let cursor: Self =
            serde_json::from_slice(&payload).map_err(|_| "object query cursor is malformed")?;
        cursor.validate(now_ms)?;
        Ok(cursor)
    }

    pub fn validate(&self, now_ms: i64) -> Result<(), String> {
        if self.contract_version != OBJECT_QUERY_CURSOR_VERSION
            || self.offset < 0
            || self.expires_at_ms <= now_ms
        {
            return Err("object query cursor is stale or unsupported".into());
        }
        validate_hex_digest("principal_context_digest", &self.principal_context_digest)?;
        validate_identity("namespace", &self.namespace)?;
        validate_digest_or_legacy("policy_activation_digest", &self.policy_activation_digest)?;
        validate_hex_digest("query_digest", &self.query_digest)
    }
}

pub fn object_query_digest(filter: &ListFilter) -> Result<String, String> {
    let mut bound = filter.clone();
    bound.offset = 0;
    canonical_hex_digest("object_query", &bound)
}

pub fn object_security_activation_digest(
    activation: &ObjectSecurityActivation,
) -> Result<String, String> {
    canonical_hex_digest(
        "object_security_activation",
        &(
            &activation.namespace,
            &activation.activation_id,
            &activation.policies,
        ),
    )
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
        if let Some(grants) = &mut self.property_grants {
            if grants.len() > MAX_PROPERTY_GRANTS {
                return Err(format!(
                    "policy must contain at most {MAX_PROPERTY_GRANTS} property grants"
                ));
            }
            for grant in grants.iter() {
                validate_property(&grant.property)?;
            }
            grants.sort_by(|left, right| {
                left.property
                    .cmp(&right.property)
                    .then(left.access.as_str().cmp(right.access.as_str()))
            });
            grants.dedup();
        }
        if let Some(purpose) = &self.required_purpose {
            validate_identity("required_purpose", purpose)?;
        }
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

    pub fn allows(
        &self,
        context: &PrincipalPolicyContext,
        object: &Object,
        operation: ObjectSecurityOperation,
    ) -> bool {
        if self.namespace != object.namespace || self.kind != object.kind {
            return false;
        }
        let context = context.clone().normalized();
        self.rules.iter().any(|rule| {
            rule.operation == operation
                && rule
                    .predicates
                    .iter()
                    .all(|predicate| predicate.matches(&context, object))
        })
    }

    pub fn policy_driving_properties(&self) -> Vec<String> {
        let mut properties = self
            .rules
            .iter()
            .flat_map(|rule| rule.predicates.iter())
            .filter_map(|predicate| match predicate {
                ObjectSecurityPredicate::SubjectEqualsProperty { property }
                | ObjectSecurityPredicate::PropertyEquals { property, .. } => {
                    Some(property.clone())
                }
                ObjectSecurityPredicate::AllowAll
                | ObjectSecurityPredicate::RequiredScopeEquals { .. } => None,
            })
            .collect::<Vec<_>>();
        properties.sort();
        properties.dedup();
        properties
    }

    pub fn property_grants_enforced(&self) -> bool {
        self.property_grants.is_some()
    }

    pub fn allows_property_access(&self, property: &str, access: PropertyGrantAccess) -> bool {
        match &self.property_grants {
            None => true,
            Some(grants) => grants
                .iter()
                .any(|grant| grant.property == property && grant.access == access),
        }
    }

    pub fn project_visible_properties(&self, object: &mut Object) {
        let Some(grants) = &self.property_grants else {
            return;
        };
        let readable = grants
            .iter()
            .filter(|grant| grant.access == PropertyGrantAccess::Read)
            .map(|grant| grant.property.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        object
            .properties
            .retain(|property, _| readable.contains(property.as_str()));
    }

    pub fn preserve_unwritable_properties(&self, existing: &Object, object: &mut Object) {
        if !self.property_grants_enforced() {
            return;
        }
        for (property, value) in &existing.properties {
            if !self.allows_property_access(property, PropertyGrantAccess::Write)
                && !object.properties.contains_key(property)
            {
                object.properties.insert(property.clone(), value.clone());
            }
        }
    }

    pub fn apply_property_grant_mutation(
        &self,
        existing: Option<&Object>,
        object: &mut Object,
    ) -> Result<(), String> {
        if !self.property_grants_enforced() {
            return Ok(());
        }
        if let Some(existing) = existing {
            for (property, value) in &existing.properties {
                if !self.allows_property_access(property, PropertyGrantAccess::Write) {
                    object.properties.insert(property.clone(), value.clone());
                }
            }
            for (property, value) in &object.properties {
                if existing.properties.get(property) != Some(value)
                    && !self.allows_property_access(property, PropertyGrantAccess::Write)
                {
                    return Err("object_security_denied: property mutation is not granted".into());
                }
            }
            return Ok(());
        }
        for property in object.properties.keys() {
            if !self.allows_property_access(property, PropertyGrantAccess::Write) {
                return Err("object_security_denied: property mutation is not granted".into());
            }
        }
        Ok(())
    }
}

fn validate_json_shape(value: &serde_json::Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "object-security policy must be a JSON object".to_string())?;
    reject_unknown_keys(
        object,
        &[
            "contract_version",
            "namespace",
            "kind",
            "rules",
            "property_grants",
            "required_purpose",
        ],
    )?;
    if let Some(grants) = object.get("property_grants") {
        let grants = grants
            .as_array()
            .ok_or_else(|| "object-security property grants must be an array".to_string())?;
        for grant in grants {
            let grant = grant
                .as_object()
                .ok_or_else(|| "object-security property grant must be an object".to_string())?;
            reject_unknown_keys(grant, &["property", "access"])?;
            let access = grant
                .get("access")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "object-security property grant access required".to_string())?;
            PropertyGrantAccess::parse(access)?;
        }
    }
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

    fn matches(&self, context: &PrincipalPolicyContext, object: &Object) -> bool {
        match self {
            Self::AllowAll => true,
            Self::SubjectEqualsProperty { property } => object
                .properties
                .get(property)
                .is_some_and(|value| context.subjects.iter().any(|subject| subject == value)),
            Self::RequiredScopeEquals { value } => {
                context.scopes.iter().any(|scope| scope == value)
            }
            Self::PropertyEquals { property, value } => object
                .properties
                .get(property)
                .is_some_and(|found| found == value),
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

fn canonical_hex_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_hex_digest(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must be a 64-character hexadecimal digest"));
    }
    Ok(())
}

fn validate_digest_or_legacy(field: &str, value: &str) -> Result<(), String> {
    if value == "legacy" {
        Ok(())
    } else {
        validate_hex_digest(field, value)
    }
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

    fn sample_object(owner: &str) -> Object {
        Object {
            id: "object-1".into(),
            kind: "document".into(),
            name: "doc".into(),
            namespace: "acme".into(),
            external_id: "document:1".into(),
            properties: std::collections::HashMap::from([("owner".into(), owner.into())]),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn read_rules_do_not_grant_writes() {
        let policy = ObjectSecurityPolicy::from_canonical_input(&document(serde_json::json!([
            {"operation":"read","predicates":[{"kind":"allow_all"}]}
        ])))
        .unwrap();
        let context = PrincipalPolicyContext {
            subjects: vec!["alice".into()],
            scopes: Vec::new(),
        };
        let object = sample_object("alice");
        assert!(policy.allows(&context, &object, ObjectSecurityOperation::Read));
        assert!(!policy.allows(&context, &object, ObjectSecurityOperation::Update));
        assert!(!policy.allows(&context, &object, ObjectSecurityOperation::Create));
    }

    #[test]
    fn matching_update_rule_authorizes_current_and_proposed_state() {
        let policy = ObjectSecurityPolicy::from_canonical_input(&document(serde_json::json!([
            {"operation":"update","predicates":[{"kind":"subject_equals_property","property":"owner"}]}
        ])))
        .unwrap();
        let alice = PrincipalPolicyContext {
            subjects: vec!["alice".into()],
            scopes: Vec::new(),
        };
        assert!(policy.allows(
            &alice,
            &sample_object("alice"),
            ObjectSecurityOperation::Update
        ));
        assert!(!policy.allows(
            &alice,
            &sample_object("bob"),
            ObjectSecurityOperation::Update
        ));
    }

    #[test]
    fn omitted_property_grants_keep_v1_digest_and_expose_all_properties() {
        let without_grants =
            ObjectSecurityPolicy::from_canonical_input(&document(serde_json::json!(
                [{"operation":"read","predicates":[{"kind":"allow_all"}]}]
            )))
            .unwrap();
        assert!(!without_grants.property_grants_enforced());
        assert!(without_grants.allows_property_access("secret", PropertyGrantAccess::Read));
        assert!(without_grants.allows_property_access("secret", PropertyGrantAccess::Write));
        let mut object = sample_object("alice");
        object
            .properties
            .insert("secret".into(), "classified".into());
        without_grants.project_visible_properties(&mut object);
        assert_eq!(
            object.properties.get("secret").map(String::as_str),
            Some("classified")
        );
        let canonical =
            serde_json::from_slice::<serde_json::Value>(&without_grants.canonical_bytes().unwrap())
                .unwrap();
        assert!(canonical.get("property_grants").is_none());
    }

    #[test]
    fn explicit_property_grants_omit_hidden_values_and_deny_unknown_access() {
        let mut input = serde_json::from_slice::<serde_json::Value>(&document(serde_json::json!([
            {"operation":"read","predicates":[{"kind":"allow_all"}]}
        ])))
        .unwrap();
        input["property_grants"] = serde_json::json!([
            {"property":"owner","access":"write"},
            {"property":"owner","access":"read"},
            {"property":"state","access":"read"}
        ]);
        let policy =
            ObjectSecurityPolicy::from_canonical_input(&serde_json::to_vec(&input).unwrap())
                .unwrap();
        assert!(policy.property_grants_enforced());
        assert!(policy.allows_property_access("owner", PropertyGrantAccess::Read));
        assert!(policy.allows_property_access("owner", PropertyGrantAccess::Write));
        assert!(policy.allows_property_access("state", PropertyGrantAccess::Read));
        assert!(!policy.allows_property_access("state", PropertyGrantAccess::Write));
        assert!(!policy.allows_property_access("secret", PropertyGrantAccess::Read));
        let mut object = sample_object("alice");
        object.properties.insert("state".into(), "open".into());
        object
            .properties
            .insert("secret".into(), "classified".into());
        policy.project_visible_properties(&mut object);
        assert_eq!(
            object.properties.get("owner").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            object.properties.get("state").map(String::as_str),
            Some("open")
        );
        assert!(!object.properties.contains_key("secret"));

        input["property_grants"] = serde_json::json!([{"property":"owner","access":"admin"}]);
        assert!(
            ObjectSecurityPolicy::from_canonical_input(&serde_json::to_vec(&input).unwrap())
                .is_err()
        );
        input["property_grants"] =
            serde_json::json!([{"property":"owner","access":"read","extra":true}]);
        assert!(
            ObjectSecurityPolicy::from_canonical_input(&serde_json::to_vec(&input).unwrap())
                .is_err()
        );
        input["property_grants"] = serde_json::json!([]);
        let empty =
            ObjectSecurityPolicy::from_canonical_input(&serde_json::to_vec(&input).unwrap())
                .unwrap();
        let mut hidden = sample_object("alice");
        empty.project_visible_properties(&mut hidden);
        assert!(hidden.properties.is_empty());
    }

    #[test]
    fn property_grant_mutation_preserves_hidden_values_and_denies_ungranted_writes() {
        let mut input = serde_json::from_slice::<serde_json::Value>(&document(serde_json::json!([
            {"operation":"update","predicates":[{"kind":"allow_all"}]}
        ])))
        .unwrap();
        input["property_grants"] = serde_json::json!([
            {"property":"owner","access":"read"},
            {"property":"owner","access":"write"}
        ]);
        let policy =
            ObjectSecurityPolicy::from_canonical_input(&serde_json::to_vec(&input).unwrap())
                .unwrap();
        let existing = {
            let mut object = sample_object("alice");
            object
                .properties
                .insert("secret".into(), "classified".into());
            object
        };
        let mut proposed = sample_object("alice");
        policy
            .apply_property_grant_mutation(Some(&existing), &mut proposed)
            .unwrap();
        assert_eq!(
            proposed.properties.get("secret").map(String::as_str),
            Some("classified")
        );

        proposed.properties.insert("secret".into(), "leaked".into());
        policy
            .apply_property_grant_mutation(Some(&existing), &mut proposed)
            .unwrap();
        assert_eq!(
            proposed.properties.get("secret").map(String::as_str),
            Some("classified")
        );

        let mut created = sample_object("alice");
        created
            .properties
            .insert("secret".into(), "classified".into());
        assert!(
            policy
                .apply_property_grant_mutation(None, &mut created)
                .unwrap_err()
                .contains("object_security_denied")
        );

        let mut inbound = sample_object("alice");
        inbound
            .properties
            .insert("sync_source".into(), "github".into());
        policy.preserve_unwritable_properties(&existing, &mut inbound);
        assert_eq!(
            inbound.properties.get("secret").map(String::as_str),
            Some("classified")
        );
        assert_eq!(
            inbound.properties.get("sync_source").map(String::as_str),
            Some("github")
        );
    }

    #[test]
    fn object_query_cursor_binds_context_policy_query_and_expiry() {
        let key = [7u8; 32];
        let cursor = ObjectQueryCursor::issue(
            10,
            "a".repeat(64),
            "acme".into(),
            "legacy".into(),
            "b".repeat(64),
            1_000,
        )
        .unwrap();
        let token = cursor.encode(&key).unwrap();
        assert_eq!(
            ObjectQueryCursor::decode(&token, &key, 1_001).unwrap(),
            cursor
        );
        assert!(ObjectQueryCursor::decode(&token, &[8u8; 32], 1_001).is_err());
        assert!(
            ObjectQueryCursor::decode(&token, &key, 1_000 + OBJECT_QUERY_CURSOR_TTL_MS).is_err()
        );
    }
}
