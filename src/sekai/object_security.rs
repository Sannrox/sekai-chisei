//! Versioned object-type security policies and authorization predicates.
//!
//! Policies are namespace scoped, immutable, and deny by default. A policy is
//! an OR of rules; each rule is an AND of conditions. An empty rule is the
//! explicit broad compatibility grant, while an empty policy denies every
//! object. Policy evaluation only consumes trusted principal context,
//! allowlisted operation context, canonical object properties, and fixed
//! values embedded in the policy.

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::{ListFilter, Object, is_valid_property_key};

pub const POLICY_CONTRACT_VERSION: &str = "sekai.object-security-policy/v1";
pub const PROFILE_CONTRACT_VERSION: &str = "sekai.object-security-profile/v1";
pub const MAX_POLICY_RULES: usize = 128;
pub const MAX_RULE_CONDITIONS: usize = 32;
pub const MAX_POLICY_IDENTIFIER_BYTES: usize = 256;
pub const MAX_POLICY_VALUE_BYTES: usize = 4_096;
pub const OBJECT_QUERY_CURSOR_TTL_MS: i64 = 5 * 60 * 1_000;

const BUILTIN_PRINCIPAL_ATTRIBUTES: &[&str] =
    &["credential_kind", "issuer", "subject", "tenant_id"];
const SUPPORTED_OPERATIONS: &[&str] = &[
    "action", "create", "delete", "export", "query", "read", "sync", "traverse", "update",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperandSource {
    Fixed,
    ObjectProperty,
    OperationContext,
    PrincipalAttribute,
    PrincipalEntitlement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Contains,
    Equals,
    NotEquals,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyOperand {
    pub source: OperandSource,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub left: PolicyOperand,
    pub operator: ConditionOperator,
    pub right: PolicyOperand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityRule {
    pub rule_id: String,
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityPolicyInput {
    pub namespace: String,
    pub object_kind: String,
    pub revision: String,
    #[serde(default)]
    pub rules: Vec<ObjectSecurityRule>,
    #[serde(default)]
    pub policy_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityPolicyRevision {
    pub contract_version: String,
    pub namespace: String,
    pub object_kind: String,
    pub revision: String,
    pub rules: Vec<ObjectSecurityRule>,
    pub policy_digest: String,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityPolicyRevocation {
    pub namespace: String,
    pub policy_digest: String,
    pub reason: String,
    pub revoked_by: String,
    pub revoked_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityPolicyRecord {
    pub policy: ObjectSecurityPolicyRevision,
    pub revocation: Option<ObjectSecurityPolicyRevocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectSecurityPolicyBinding {
    pub object_kind: String,
    pub policy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateObjectSecurityProfile {
    pub namespace: String,
    #[serde(default)]
    pub expected_profile_digest: String,
    pub bindings: Vec<ObjectSecurityPolicyBinding>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSecurityProfile {
    pub contract_version: String,
    pub namespace: String,
    pub profile_digest: String,
    pub bindings: Vec<ObjectSecurityPolicyBinding>,
    pub activated_by: String,
    pub activated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeObjectSecurityPolicy {
    pub namespace: String,
    pub policy_digest: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ObjectSecurityWriteResult {
    CreatePolicy { record: ObjectSecurityPolicyRecord },
    ActivateProfile { profile: ObjectSecurityProfile },
    RevokePolicy { record: ObjectSecurityPolicyRecord },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrincipalSecurityContext {
    pub attributes: BTreeMap<String, String>,
    pub entitlements: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAuthorizationContext {
    pub principal: PrincipalSecurityContext,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAuthorizationDecision {
    pub allowed: bool,
    pub policy_digest: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectQueryCursor {
    pub contract_version: String,
    pub offset: i32,
    pub principal_context_digest: String,
    pub namespace: String,
    pub policy_profile_digest: String,
    pub query_digest: String,
    pub expires_at_ms: i64,
}

const OBJECT_QUERY_CURSOR_VERSION: &str = "sekai.object-query-cursor/v1";

impl ObjectQueryCursor {
    pub fn issue(
        offset: i32,
        principal_context_digest: String,
        namespace: String,
        policy_profile_digest: String,
        query_digest: String,
        now_ms: i64,
    ) -> Result<Self, String> {
        if offset < 0 || now_ms <= 0 {
            return Err("object query cursor position or issuance time is invalid".into());
        }
        validate_digest("principal_context_digest", &principal_context_digest)?;
        validate_identifier("namespace", &namespace)?;
        validate_digest_or_legacy("policy_profile_digest", &policy_profile_digest)?;
        validate_digest("query_digest", &query_digest)?;
        Ok(Self {
            contract_version: OBJECT_QUERY_CURSOR_VERSION.into(),
            offset,
            principal_context_digest,
            namespace,
            policy_profile_digest,
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
        validate_digest("principal_context_digest", &self.principal_context_digest)?;
        validate_identifier("namespace", &self.namespace)?;
        validate_digest_or_legacy("policy_profile_digest", &self.policy_profile_digest)?;
        validate_digest("query_digest", &self.query_digest)
    }
}

pub fn object_query_digest(filter: &ListFilter) -> Result<String, String> {
    let mut bound = filter.clone();
    bound.offset = 0;
    canonical_digest("object_query", &bound)
}

pub fn object_security_profile_state_digest(
    profile: &ObjectSecurityProfile,
    records: &[ObjectSecurityPolicyRecord],
) -> Result<String, String> {
    profile.verify()?;
    let mut ordered = Vec::with_capacity(profile.bindings.len());
    for binding in &profile.bindings {
        let mut matches = records.iter().filter(|record| {
            record.policy.namespace == profile.namespace
                && record.policy.object_kind == binding.object_kind
                && record.policy.policy_digest == binding.policy_digest
        });
        let record = matches
            .next()
            .ok_or_else(|| "object security profile state is incomplete".to_string())?;
        if matches.next().is_some() {
            return Err("object security profile state is ambiguous".into());
        }
        ordered.push(record);
    }
    canonical_digest("object_security_profile_state", &(profile, ordered))
}

impl ObjectSecurityPolicyInput {
    pub fn prepare(
        &self,
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityPolicyRevision, String> {
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("object_kind", &self.object_kind)?;
        validate_identifier("revision", &self.revision)?;
        validate_identifier("idempotency_key", &self.idempotency_key)?;
        validate_identifier("created_by", actor)?;
        if now_ms <= 0 {
            return Err("created_at_ms must be positive".into());
        }
        if self.rules.len() > MAX_POLICY_RULES {
            return Err("object security policy exceeds the supported rule count".into());
        }

        let mut rules = self.rules.clone();
        let mut rule_ids = BTreeSet::new();
        for rule in &mut rules {
            validate_identifier("rule_id", &rule.rule_id)?;
            if !rule_ids.insert(rule.rule_id.clone()) {
                return Err("object security policy contains duplicate rule ids".into());
            }
            if rule.conditions.len() > MAX_RULE_CONDITIONS {
                return Err("object security rule exceeds the supported condition count".into());
            }
            for condition in &rule.conditions {
                condition.validate()?;
            }
            rule.conditions.sort();
            rule.conditions.dedup();
        }
        rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));

        let policy_digest =
            policy_digest(&self.namespace, &self.object_kind, &self.revision, &rules)?;
        if !self.policy_digest.is_empty() && self.policy_digest != policy_digest {
            return Err("policy_digest does not match canonical policy content".into());
        }
        Ok(ObjectSecurityPolicyRevision {
            contract_version: POLICY_CONTRACT_VERSION.into(),
            namespace: self.namespace.clone(),
            object_kind: self.object_kind.clone(),
            revision: self.revision.clone(),
            rules,
            policy_digest,
            created_by: actor.into(),
            created_at_ms: now_ms,
        })
    }

    pub fn request_digest(&self, actor: &str, now_ms: i64) -> Result<String, String> {
        let prepared = self.prepare(actor, now_ms)?;
        canonical_digest(
            "create_object_security_policy",
            &(
                &prepared.namespace,
                &prepared.object_kind,
                &prepared.revision,
                &prepared.rules,
                actor,
            ),
        )
    }
}

impl ObjectSecurityPolicyRevision {
    pub fn verify(&self) -> Result<(), String> {
        if self.contract_version != POLICY_CONTRACT_VERSION {
            return Err("object security policy contract version is unsupported".into());
        }
        let prepared = ObjectSecurityPolicyInput {
            namespace: self.namespace.clone(),
            object_kind: self.object_kind.clone(),
            revision: self.revision.clone(),
            rules: self.rules.clone(),
            policy_digest: self.policy_digest.clone(),
            idempotency_key: "verification".into(),
        }
        .prepare(&self.created_by, self.created_at_ms)?;
        if prepared != *self {
            return Err("object security policy content binding is invalid".into());
        }
        Ok(())
    }

    pub(crate) fn driving_property_keys(&self) -> BTreeSet<String> {
        self.rules
            .iter()
            .flat_map(|rule| &rule.conditions)
            .flat_map(|condition| [&condition.left, &condition.right])
            .filter(|operand| operand.source == OperandSource::ObjectProperty)
            .map(|operand| operand.name.clone())
            .collect()
    }
}

impl ObjectSecurityPolicyRecord {
    pub(crate) fn snapshot_property_keys(&self) -> BTreeSet<String> {
        if self.revocation.is_some() {
            return BTreeSet::new();
        }
        self.policy.driving_property_keys()
    }
}

impl PolicyCondition {
    pub fn validate(&self) -> Result<(), String> {
        self.left.validate()?;
        self.right.validate()?;
        let object_operands = [&self.left, &self.right]
            .into_iter()
            .filter(|operand| operand.source == OperandSource::ObjectProperty)
            .count();
        if object_operands > 1 {
            return Err("a policy condition may reference at most one object property".into());
        }
        if self.operator == ConditionOperator::Contains
            && self.left.source != OperandSource::PrincipalEntitlement
            && self.right.source != OperandSource::PrincipalEntitlement
        {
            return Err("contains is supported only for principal entitlements".into());
        }
        Ok(())
    }
}

impl PolicyOperand {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.len() > MAX_POLICY_IDENTIFIER_BYTES
            || self.value.len() > MAX_POLICY_VALUE_BYTES
        {
            return Err("policy operand exceeds the supported size".into());
        }
        match self.source {
            OperandSource::Fixed => {
                if !self.name.is_empty() {
                    return Err("fixed operands must not set name".into());
                }
            }
            OperandSource::ObjectProperty => {
                if !self.value.is_empty() || !is_valid_property_key(&self.name) {
                    return Err(
                        "object_property operands require a canonical property name and no value"
                            .into(),
                    );
                }
            }
            OperandSource::OperationContext => {
                if self.name != "operation" || !self.value.is_empty() {
                    return Err(
                        "operation_context operands support only the operation field".into(),
                    );
                }
            }
            OperandSource::PrincipalAttribute => {
                if !self.value.is_empty() || !is_valid_property_key(&self.name) {
                    return Err(
                        "principal_attribute operands require an allowlisted attribute name and no value"
                            .into(),
                    );
                }
            }
            OperandSource::PrincipalEntitlement => {
                if !self.name.is_empty() || !self.value.is_empty() {
                    return Err("principal_entitlement operands do not accept name or value".into());
                }
            }
        }
        Ok(())
    }
}

impl ActivateObjectSecurityProfile {
    pub fn prepare(
        &self,
        advertised_object_kinds: impl IntoIterator<Item = String>,
        actor: &str,
        now_ms: i64,
    ) -> Result<(ObjectSecurityProfile, String), String> {
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("idempotency_key", &self.idempotency_key)?;
        validate_identifier("activated_by", actor)?;
        if now_ms <= 0 {
            return Err("activated_at_ms must be positive".into());
        }
        if !self.expected_profile_digest.is_empty() {
            validate_digest("expected_profile_digest", &self.expected_profile_digest)?;
        }

        let expected = advertised_object_kinds
            .into_iter()
            .filter(|kind| !kind.trim().is_empty())
            .collect::<BTreeSet<_>>();
        let mut bindings = self.bindings.clone();
        for binding in &bindings {
            validate_identifier("object_kind", &binding.object_kind)?;
            validate_digest("policy_digest", &binding.policy_digest)?;
        }
        bindings.sort();
        if bindings
            .windows(2)
            .any(|pair| pair[0].object_kind == pair[1].object_kind)
        {
            return Err("object security profile contains duplicate object types".into());
        }
        let actual = bindings
            .iter()
            .map(|binding| binding.object_kind.clone())
            .collect::<BTreeSet<_>>();
        if expected != actual {
            return Err(
                "object security profile must bind every advertised object type exactly once"
                    .into(),
            );
        }
        let profile_digest = profile_digest(&self.namespace, &bindings)?;
        let request_digest = self.request_digest(actor)?;
        Ok((
            ObjectSecurityProfile {
                contract_version: PROFILE_CONTRACT_VERSION.into(),
                namespace: self.namespace.clone(),
                profile_digest,
                bindings,
                activated_by: actor.into(),
                activated_at_ms: now_ms,
            },
            request_digest,
        ))
    }

    pub fn request_digest(&self, actor: &str) -> Result<String, String> {
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("activated_by", actor)?;
        if !self.expected_profile_digest.is_empty() {
            validate_digest("expected_profile_digest", &self.expected_profile_digest)?;
        }
        let mut bindings = self.bindings.clone();
        for binding in &bindings {
            validate_identifier("object_kind", &binding.object_kind)?;
            validate_digest("policy_digest", &binding.policy_digest)?;
        }
        bindings.sort();
        canonical_digest(
            "activate_object_security_profile",
            &(
                &self.namespace,
                &self.expected_profile_digest,
                &bindings,
                actor,
            ),
        )
    }
}

impl ObjectSecurityProfile {
    pub fn verify(&self) -> Result<(), String> {
        if self.contract_version != PROFILE_CONTRACT_VERSION {
            return Err("object security profile contract version is unsupported".into());
        }
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("activated_by", &self.activated_by)?;
        if self.activated_at_ms <= 0 {
            return Err("activated_at_ms must be positive".into());
        }
        for binding in &self.bindings {
            validate_identifier("object_kind", &binding.object_kind)?;
            validate_digest("policy_digest", &binding.policy_digest)?;
        }
        if self
            .bindings
            .windows(2)
            .any(|pair| pair[0].object_kind >= pair[1].object_kind)
        {
            return Err("object security profile bindings are not canonical".into());
        }
        if profile_digest(&self.namespace, &self.bindings)? != self.profile_digest {
            return Err("object security profile content binding is invalid".into());
        }
        Ok(())
    }

    pub fn policy_digest_for(&self, object_kind: &str) -> Option<&str> {
        self.bindings
            .binary_search_by(|binding| binding.object_kind.as_str().cmp(object_kind))
            .ok()
            .map(|index| self.bindings[index].policy_digest.as_str())
    }
}

impl RevokeObjectSecurityPolicy {
    pub fn validate(&self, actor: &str, now_ms: i64) -> Result<String, String> {
        validate_identifier("namespace", &self.namespace)?;
        validate_digest("policy_digest", &self.policy_digest)?;
        validate_identifier("idempotency_key", &self.idempotency_key)?;
        validate_identifier("revoked_by", actor)?;
        if self.reason.trim().is_empty() || self.reason.len() > MAX_POLICY_VALUE_BYTES {
            return Err("revocation reason is required and must be bounded".into());
        }
        if now_ms <= 0 {
            return Err("revoked_at_ms must be positive".into());
        }
        canonical_digest(
            "revoke_object_security_policy",
            &(
                &self.namespace,
                &self.policy_digest,
                self.reason.trim(),
                actor,
            ),
        )
    }
}

impl ObjectAuthorizationContext {
    pub fn validate(&self) -> Result<(), String> {
        if !SUPPORTED_OPERATIONS.contains(&self.operation.as_str()) {
            return Err("unsupported object authorization operation".into());
        }
        for (name, value) in &self.principal.attributes {
            if !is_valid_property_key(name)
                || name.len() > MAX_POLICY_IDENTIFIER_BYTES
                || value.len() > MAX_POLICY_VALUE_BYTES
            {
                return Err("trusted principal attribute is invalid or exceeds bounds".into());
            }
        }
        if !self.principal.attributes.keys().all(|name| {
            BUILTIN_PRINCIPAL_ATTRIBUTES.contains(&name.as_str()) || name.starts_with("x_")
        }) {
            return Err("trusted principal attribute is not allowlisted".into());
        }
        if self
            .principal
            .entitlements
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > MAX_POLICY_IDENTIFIER_BYTES)
        {
            return Err("principal entitlement is invalid or exceeds bounds".into());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        canonical_digest(
            "object_authorization_context",
            &(
                &self.principal.attributes,
                &self.principal.entitlements,
                &self.operation,
            ),
        )
    }
}

pub fn evaluate_object_policy(
    policy: &ObjectSecurityPolicyRevision,
    context: &ObjectAuthorizationContext,
    object: &Object,
) -> Result<ObjectAuthorizationDecision, String> {
    policy.verify()?;
    context.validate()?;
    if policy.namespace != object.namespace || policy.object_kind != object.kind {
        return Ok(ObjectAuthorizationDecision {
            allowed: false,
            policy_digest: policy.policy_digest.clone(),
            reason: "policy_scope_mismatch",
        });
    }
    for rule in &policy.rules {
        let mut matched = true;
        for condition in &rule.conditions {
            if !evaluate_condition(condition, context, object)? {
                matched = false;
                break;
            }
        }
        if matched {
            return Ok(ObjectAuthorizationDecision {
                allowed: true,
                policy_digest: policy.policy_digest.clone(),
                reason: "rule_match",
            });
        }
    }
    Ok(ObjectAuthorizationDecision {
        allowed: false,
        policy_digest: policy.policy_digest.clone(),
        reason: "no_rule_match",
    })
}

fn evaluate_condition(
    condition: &PolicyCondition,
    context: &ObjectAuthorizationContext,
    object: &Object,
) -> Result<bool, String> {
    condition.validate()?;
    let left = resolve_operand(&condition.left, context, object);
    let right = resolve_operand(&condition.right, context, object);
    let result = match (condition.operator, left, right) {
        (
            ConditionOperator::Equals,
            ResolvedOperand::Scalar(Some(left)),
            ResolvedOperand::Scalar(Some(right)),
        ) => left == right,
        (
            ConditionOperator::NotEquals,
            ResolvedOperand::Scalar(Some(left)),
            ResolvedOperand::Scalar(Some(right)),
        ) => left != right,
        (
            ConditionOperator::Contains,
            ResolvedOperand::Set(left),
            ResolvedOperand::Scalar(Some(right)),
        ) => left.contains(&right),
        (
            ConditionOperator::Contains,
            ResolvedOperand::Scalar(Some(left)),
            ResolvedOperand::Set(right),
        ) => right.contains(&left),
        _ => false,
    };
    Ok(result)
}

enum ResolvedOperand {
    Scalar(Option<String>),
    Set(BTreeSet<String>),
}

fn resolve_operand(
    operand: &PolicyOperand,
    context: &ObjectAuthorizationContext,
    object: &Object,
) -> ResolvedOperand {
    match operand.source {
        OperandSource::Fixed => ResolvedOperand::Scalar(Some(operand.value.clone())),
        OperandSource::ObjectProperty => {
            ResolvedOperand::Scalar(object.properties.get(&operand.name).cloned())
        }
        OperandSource::OperationContext => ResolvedOperand::Scalar(Some(context.operation.clone())),
        OperandSource::PrincipalAttribute => {
            ResolvedOperand::Scalar(context.principal.attributes.get(&operand.name).cloned())
        }
        OperandSource::PrincipalEntitlement => {
            ResolvedOperand::Set(context.principal.entitlements.clone())
        }
    }
}

fn policy_digest(
    namespace: &str,
    object_kind: &str,
    revision: &str,
    rules: &[ObjectSecurityRule],
) -> Result<String, String> {
    canonical_digest(
        "object_security_policy",
        &(
            POLICY_CONTRACT_VERSION,
            namespace,
            object_kind,
            revision,
            rules,
        ),
    )
}

fn profile_digest(
    namespace: &str,
    bindings: &[ObjectSecurityPolicyBinding],
) -> Result<String, String> {
    canonical_digest(
        "object_security_profile",
        &(PROFILE_CONTRACT_VERSION, namespace, bindings),
    )
}

fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&value)?;
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(canonical);
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_identifier(field: &str, value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} is required"));
    }
    if value.len() > MAX_POLICY_IDENTIFIER_BYTES {
        return Err(format!("{field} exceeds the supported size"));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must be a 64-character hexadecimal digest"));
    }
    Ok(())
}

fn validate_digest_or_legacy(field: &str, value: &str) -> Result<(), String> {
    if value == "legacy" {
        Ok(())
    } else {
        validate_digest(field, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fixed(value: &str) -> PolicyOperand {
        PolicyOperand {
            source: OperandSource::Fixed,
            name: String::new(),
            value: value.into(),
        }
    }

    fn object_property(name: &str) -> PolicyOperand {
        PolicyOperand {
            source: OperandSource::ObjectProperty,
            name: name.into(),
            value: String::new(),
        }
    }

    fn context(subject: &str, operation: &str) -> ObjectAuthorizationContext {
        ObjectAuthorizationContext {
            principal: PrincipalSecurityContext {
                attributes: BTreeMap::from([("subject".into(), subject.into())]),
                entitlements: BTreeSet::new(),
            },
            operation: operation.into(),
        }
    }

    fn object(owner: &str) -> Object {
        Object {
            id: "object-1".into(),
            kind: "artifact".into(),
            name: "artifact".into(),
            namespace: "ns".into(),
            external_id: "artifact:1".into(),
            properties: HashMap::from([("owner".into(), owner.into())]),
            created: 1,
            updated: 1,
        }
    }

    fn policy(rules: Vec<ObjectSecurityRule>) -> ObjectSecurityPolicyRevision {
        ObjectSecurityPolicyInput {
            namespace: "ns".into(),
            object_kind: "artifact".into(),
            revision: "1".into(),
            rules,
            policy_digest: String::new(),
            idempotency_key: "request-1".into(),
        }
        .prepare("root", 1)
        .unwrap()
    }

    #[test]
    fn empty_policy_denies_and_empty_rule_is_explicit_broad_allow() {
        let denied = evaluate_object_policy(
            &policy(Vec::new()),
            &context("alice", "read"),
            &object("alice"),
        )
        .unwrap();
        assert!(!denied.allowed);

        let allowed = evaluate_object_policy(
            &policy(vec![ObjectSecurityRule {
                rule_id: "broad".into(),
                conditions: Vec::new(),
            }]),
            &context("alice", "read"),
            &object("bob"),
        )
        .unwrap();
        assert!(allowed.allowed);
    }

    #[test]
    fn policy_matches_trusted_principal_attribute_to_object_property() {
        let policy = policy(vec![ObjectSecurityRule {
            rule_id: "owner".into(),
            conditions: vec![PolicyCondition {
                left: object_property("owner"),
                operator: ConditionOperator::Equals,
                right: PolicyOperand {
                    source: OperandSource::PrincipalAttribute,
                    name: "subject".into(),
                    value: String::new(),
                },
            }],
        }]);
        assert!(
            evaluate_object_policy(&policy, &context("alice", "read"), &object("alice"))
                .unwrap()
                .allowed
        );
        assert!(
            !evaluate_object_policy(&policy, &context("bob", "read"), &object("alice"))
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn missing_attributes_and_unknown_operations_deny() {
        let policy = policy(vec![ObjectSecurityRule {
            rule_id: "missing".into(),
            conditions: vec![PolicyCondition {
                left: object_property("missing"),
                operator: ConditionOperator::NotEquals,
                right: fixed("value"),
            }],
        }]);
        assert!(
            !evaluate_object_policy(&policy, &context("alice", "read"), &object("alice"))
                .unwrap()
                .allowed
        );
        assert!(context("alice", "unknown").validate().is_err());
    }

    #[test]
    fn profile_requires_complete_exact_type_bindings() {
        let digest = "a".repeat(64);
        let request = ActivateObjectSecurityProfile {
            namespace: "ns".into(),
            expected_profile_digest: String::new(),
            bindings: vec![ObjectSecurityPolicyBinding {
                object_kind: "artifact".into(),
                policy_digest: digest,
            }],
            idempotency_key: "activate-1".into(),
        };
        assert!(request.prepare(["artifact".into()], "root", 1).is_ok());
        assert!(
            request
                .prepare(["artifact".into(), "operation".into()], "root", 1)
                .is_err()
        );
    }

    #[test]
    fn profile_rejects_multiple_policies_for_one_object_type() {
        let request = ActivateObjectSecurityProfile {
            namespace: "ns".into(),
            expected_profile_digest: String::new(),
            bindings: vec![
                ObjectSecurityPolicyBinding {
                    object_kind: "artifact".into(),
                    policy_digest: "a".repeat(64),
                },
                ObjectSecurityPolicyBinding {
                    object_kind: "artifact".into(),
                    policy_digest: "b".repeat(64),
                },
            ],
            idempotency_key: "activate-duplicate".into(),
        };
        assert!(request.prepare(["artifact".into()], "root", 1).is_err());
    }

    #[test]
    fn object_query_cursor_binds_context_policy_query_and_expiry() {
        let key = [7u8; 32];
        let cursor = ObjectQueryCursor::issue(
            100,
            "a".repeat(64),
            "ns".into(),
            "b".repeat(64),
            "c".repeat(64),
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

    #[test]
    fn profile_state_digest_changes_when_a_bound_policy_is_revoked() {
        let policy = policy(vec![ObjectSecurityRule {
            rule_id: "allow".into(),
            conditions: Vec::new(),
        }]);
        let (profile, _) = ActivateObjectSecurityProfile {
            namespace: "ns".into(),
            expected_profile_digest: String::new(),
            bindings: vec![ObjectSecurityPolicyBinding {
                object_kind: "artifact".into(),
                policy_digest: policy.policy_digest.clone(),
            }],
            idempotency_key: "activate".into(),
        }
        .prepare(["artifact".into()], "root", 2)
        .unwrap();
        let active = ObjectSecurityPolicyRecord {
            policy: policy.clone(),
            revocation: None,
        };
        let revoked = ObjectSecurityPolicyRecord {
            policy: policy.clone(),
            revocation: Some(ObjectSecurityPolicyRevocation {
                namespace: "ns".into(),
                policy_digest: policy.policy_digest,
                reason: "revoked".into(),
                revoked_by: "root".into(),
                revoked_at_ms: 3,
            }),
        };
        assert_ne!(
            object_security_profile_state_digest(&profile, &[active]).unwrap(),
            object_security_profile_state_digest(&profile, &[revoked]).unwrap()
        );
    }
}
