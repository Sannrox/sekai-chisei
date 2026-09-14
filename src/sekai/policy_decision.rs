//! One compiling policy decision point over shipped v1 vocabularies (ADR 0076).
//!
//! The crate-visible product is [`compile_object_access`]: it compiles
//! markings, namespace grants, object-security row rules, purpose, property
//! grants, and value-instance grants into one residual. Storage SQL already
//! applies the row and marking residuals before materialization; this module
//! is the authority those residuals project.
//!
//! [`evaluate_legacy_layers`] is the migration oracle. It is not the product.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::Object;
use crate::sekai::classification_lattice::{ClassificationLattice, evaluate_lattice_access};
use crate::sekai::markings::{MarkingDecision, PrincipalAuthority, object_marking_token};
use crate::sekai::object_security::{
    ObjectSecurityOperation, ObjectSecurityPolicy, PrincipalPolicyContext,
};
use crate::sekai::purpose_authorization::{
    PurposeAuthorization, PurposeEvaluation, PurposePresentation, evaluate_required_purpose,
};

pub const POLICY_DECISION_CONTRACT: &str = "sekai.policy-decision/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    Marking,
    NamespaceGrant,
    ObjectRow,
    Purpose,
    Property,
    ValueInstance,
}

impl PolicyLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Marking => "marking",
            Self::NamespaceGrant => "namespace_grant",
            Self::ObjectRow => "object_row",
            Self::Purpose => "purpose",
            Self::Property => "property",
            Self::ValueInstance => "value_instance",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "marking" => Ok(Self::Marking),
            "namespace_grant" => Ok(Self::NamespaceGrant),
            "object_row" => Ok(Self::ObjectRow),
            "purpose" => Ok(Self::Purpose),
            "property" => Ok(Self::Property),
            "value_instance" => Ok(Self::ValueInstance),
            _ => Err("unsupported policy layer".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Deny,
}

impl PolicyOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err("unsupported policy outcome".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub contract_version: String,
    pub namespace: String,
    pub object_kind: String,
    pub object_id: String,
    pub operation: String,
    pub principal: String,
    pub principal_digest: String,
    pub activation_digest: String,
    pub policy_revision_digest: String,
    pub outcome: PolicyOutcome,
    pub denied_by: Option<PolicyLayer>,
}

impl PolicyDecision {
    pub fn export_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionRecord {
    pub event_id: String,
    pub decision: PolicyDecision,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyDecisionQuery {
    pub namespace: String,
    pub principal: String,
    pub object_id: String,
    pub from_ms: i64,
    pub to_ms: i64,
    pub limit: i32,
    pub offset: i32,
}

#[derive(Debug, Clone)]
pub struct PolicyCompileRequest<'a> {
    pub namespace: &'a str,
    pub kind: &'a str,
    pub operation: ObjectSecurityOperation,
    pub context: &'a PrincipalPolicyContext,
    pub authority: &'a PrincipalAuthority,
    pub lattice: Option<&'a ClassificationLattice>,
    pub policy: Option<&'a ObjectSecurityPolicy>,
    pub activation_digest: &'a str,
    pub purpose: Option<&'a PurposePresentation>,
    pub purpose_authorization: Option<&'a PurposeAuthorization>,
    pub now_ms: i64,
    pub namespace_granted: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledObjectAccess {
    namespace: String,
    kind: String,
    operation: ObjectSecurityOperation,
    context: PrincipalPolicyContext,
    authority: PrincipalAuthority,
    lattice: Option<ClassificationLattice>,
    policy: Option<ObjectSecurityPolicy>,
    activation_digest: String,
    policy_revision_digest: String,
    principal_digest: String,
    purpose: Option<PurposePresentation>,
    purpose_authorization: Option<PurposeAuthorization>,
    now_ms: i64,
    namespace_granted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySimulationDifference {
    pub principal: String,
    pub object_id: String,
    pub object_kind: String,
    pub property: String,
    pub current_outcome: PolicyOutcome,
    pub candidate_outcome: PolicyOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySimulationReport {
    pub namespace: String,
    pub current_activation_digest: String,
    pub candidate_digest: String,
    pub differences: Vec<PolicySimulationDifference>,
}

#[derive(Debug, Clone)]
pub struct SimulatedPrincipal {
    pub principal: String,
    pub context: PrincipalPolicyContext,
    pub authority: PrincipalAuthority,
    pub purpose: Option<PurposePresentation>,
    pub purpose_authorization: Option<PurposeAuthorization>,
    pub namespace_granted: bool,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub namespace: String,
    pub activation_digest: String,
    pub policies: BTreeMap<String, ObjectSecurityPolicy>,
    pub lattice: Option<ClassificationLattice>,
}

/// Compile shipped v1 vocabularies into one residual. This is the product.
pub fn compile_object_access(
    request: PolicyCompileRequest<'_>,
) -> Result<CompiledObjectAccess, String> {
    let context = request.context.clone().normalized();
    let principal_digest = context.digest()?;
    let policy_revision_digest = match request.policy {
        Some(policy) => policy.revision_digest()?,
        None => "legacy".into(),
    };
    Ok(CompiledObjectAccess {
        namespace: request.namespace.into(),
        kind: request.kind.into(),
        operation: request.operation,
        context,
        authority: request.authority.clone(),
        lattice: request.lattice.cloned(),
        policy: request.policy.cloned(),
        activation_digest: request.activation_digest.into(),
        policy_revision_digest,
        principal_digest,
        purpose: request.purpose.cloned(),
        purpose_authorization: request.purpose_authorization.cloned(),
        now_ms: request.now_ms,
        namespace_granted: request.namespace_granted,
    })
}

impl CompiledObjectAccess {
    pub fn decide(&self, object: &Object) -> PolicyDecision {
        let mut decision = PolicyDecision {
            contract_version: POLICY_DECISION_CONTRACT.into(),
            namespace: object.namespace.clone(),
            object_kind: object.kind.clone(),
            object_id: object.id.clone(),
            operation: self.operation.as_str().into(),
            principal: self.authority.principal.clone(),
            principal_digest: self.principal_digest.clone(),
            activation_digest: self.activation_digest.clone(),
            policy_revision_digest: self.policy_revision_digest.clone(),
            outcome: PolicyOutcome::Allow,
            denied_by: None,
        };
        if object.namespace != self.namespace || object.kind != self.kind {
            decision.outcome = PolicyOutcome::Deny;
            decision.denied_by = Some(PolicyLayer::ObjectRow);
            return decision;
        }
        let marking = evaluate_lattice_access(
            "policy-decision",
            object_marking_token(object),
            &self.authority,
            self.lattice.as_ref(),
        );
        if marking.decision == MarkingDecision::Deny {
            decision.outcome = PolicyOutcome::Deny;
            decision.denied_by = Some(PolicyLayer::Marking);
            return decision;
        }
        if !self.namespace_granted {
            decision.outcome = PolicyOutcome::Deny;
            decision.denied_by = Some(PolicyLayer::NamespaceGrant);
            return decision;
        }
        if let Some(policy) = &self.policy
            && !policy.allows(&self.context, object, self.operation)
        {
            decision.outcome = PolicyOutcome::Deny;
            decision.denied_by = Some(PolicyLayer::ObjectRow);
            return decision;
        }
        let required_purpose = self
            .policy
            .as_ref()
            .and_then(|policy| policy.required_purpose.as_deref());
        let purpose = evaluate_required_purpose(PurposeEvaluation {
            operation_id: "policy-decision",
            required_purpose,
            presentation: self.purpose.as_ref(),
            authorization: self.purpose_authorization.as_ref(),
            namespace: &self.namespace,
            kind: &self.kind,
            activation_digest: &self.activation_digest,
            now_ms: self.now_ms,
        });
        if purpose.decision == MarkingDecision::Deny {
            decision.outcome = PolicyOutcome::Deny;
            decision.denied_by = Some(PolicyLayer::Purpose);
            return decision;
        }
        decision
    }

    pub fn visible_property_names(&self, object: &Object) -> BTreeSet<String> {
        if self.decide(object).outcome != PolicyOutcome::Allow {
            return BTreeSet::new();
        }
        let mut projected = object.clone();
        self.project(&mut projected);
        projected.properties.keys().cloned().collect()
    }

    pub fn project(&self, object: &mut Object) {
        let Some(policy) = &self.policy else {
            return;
        };
        policy.project_visible_properties(object);
        policy.project_visible_value_instances(object);
    }
}

/// Migration oracle: today's evaluators in ADR 0076 order. Not the product.
pub fn evaluate_legacy_layers(
    request: PolicyCompileRequest<'_>,
    object: &Object,
) -> Result<(PolicyDecision, BTreeSet<String>), String> {
    let compiled = compile_object_access(request)?;
    let mut denied_by = None;
    if object.namespace != compiled.namespace || object.kind != compiled.kind {
        denied_by = Some(PolicyLayer::ObjectRow);
    }
    if denied_by.is_none() {
        let marking = evaluate_lattice_access(
            "legacy-migration",
            object_marking_token(object),
            &compiled.authority,
            compiled.lattice.as_ref(),
        );
        if marking.decision == MarkingDecision::Deny {
            denied_by = Some(PolicyLayer::Marking);
        }
    }
    if denied_by.is_none() && !compiled.namespace_granted {
        denied_by = Some(PolicyLayer::NamespaceGrant);
    }
    if denied_by.is_none()
        && let Some(policy) = &compiled.policy
        && !policy.allows(&compiled.context, object, compiled.operation)
    {
        denied_by = Some(PolicyLayer::ObjectRow);
    }
    if denied_by.is_none() {
        let required_purpose = compiled
            .policy
            .as_ref()
            .and_then(|policy| policy.required_purpose.as_deref());
        let purpose = evaluate_required_purpose(PurposeEvaluation {
            operation_id: "legacy-migration",
            required_purpose,
            presentation: compiled.purpose.as_ref(),
            authorization: compiled.purpose_authorization.as_ref(),
            namespace: &compiled.namespace,
            kind: &compiled.kind,
            activation_digest: &compiled.activation_digest,
            now_ms: compiled.now_ms,
        });
        if purpose.decision == MarkingDecision::Deny {
            denied_by = Some(PolicyLayer::Purpose);
        }
    }
    let outcome = if denied_by.is_some() {
        PolicyOutcome::Deny
    } else {
        PolicyOutcome::Allow
    };
    let mut visible = BTreeSet::new();
    if outcome == PolicyOutcome::Allow {
        let mut projected = object.clone();
        compiled.project(&mut projected);
        visible = projected.properties.keys().cloned().collect();
    }
    Ok((
        PolicyDecision {
            contract_version: POLICY_DECISION_CONTRACT.into(),
            namespace: object.namespace.clone(),
            object_kind: object.kind.clone(),
            object_id: object.id.clone(),
            operation: compiled.operation.as_str().into(),
            principal: compiled.authority.principal,
            principal_digest: compiled.principal_digest,
            activation_digest: compiled.activation_digest,
            policy_revision_digest: compiled.policy_revision_digest,
            outcome,
            denied_by,
        },
        visible,
    ))
}

pub fn simulate_policy_change(
    objects: &[Object],
    principals: &[SimulatedPrincipal],
    current: &PolicySnapshot,
    candidate: &PolicySnapshot,
    operation: ObjectSecurityOperation,
    now_ms: i64,
) -> Result<PolicySimulationReport, String> {
    if current.namespace != candidate.namespace {
        return Err("simulation requires one namespace".into());
    }
    let candidate_digest = snapshot_digest(candidate)?;
    let mut differences = Vec::new();
    for principal in principals {
        for object in objects {
            if object.namespace != current.namespace {
                continue;
            }
            let current_compiled =
                compile_for_snapshot(current, principal, &object.kind, operation, now_ms)?;
            let candidate_compiled =
                compile_for_snapshot(candidate, principal, &object.kind, operation, now_ms)?;
            let current_decision = current_compiled.decide(object);
            let candidate_decision = candidate_compiled.decide(object);
            if current_decision.outcome != candidate_decision.outcome {
                differences.push(PolicySimulationDifference {
                    principal: principal.principal.clone(),
                    object_id: object.id.clone(),
                    object_kind: object.kind.clone(),
                    property: String::new(),
                    current_outcome: current_decision.outcome,
                    candidate_outcome: candidate_decision.outcome,
                });
            }
            let current_props = current_compiled.visible_property_names(object);
            let candidate_props = candidate_compiled.visible_property_names(object);
            for property in current_props.symmetric_difference(&candidate_props) {
                let current_outcome = if current_props.contains(property) {
                    PolicyOutcome::Allow
                } else {
                    PolicyOutcome::Deny
                };
                let candidate_outcome = if candidate_props.contains(property) {
                    PolicyOutcome::Allow
                } else {
                    PolicyOutcome::Deny
                };
                differences.push(PolicySimulationDifference {
                    principal: principal.principal.clone(),
                    object_id: object.id.clone(),
                    object_kind: object.kind.clone(),
                    property: property.clone(),
                    current_outcome,
                    candidate_outcome,
                });
            }
        }
    }
    differences.sort_by(|left, right| {
        (
            left.principal.as_str(),
            left.object_id.as_str(),
            left.property.as_str(),
        )
            .cmp(&(
                right.principal.as_str(),
                right.object_id.as_str(),
                right.property.as_str(),
            ))
    });
    Ok(PolicySimulationReport {
        namespace: current.namespace.clone(),
        current_activation_digest: current.activation_digest.clone(),
        candidate_digest,
        differences,
    })
}

pub fn snapshot_digest(snapshot: &PolicySnapshot) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.policy-snapshot/v1\0");
    hasher.update(snapshot.namespace.as_bytes());
    hasher.update([0]);
    hasher.update(snapshot.activation_digest.as_bytes());
    for (kind, policy) in &snapshot.policies {
        hasher.update(kind.as_bytes());
        hasher.update([0]);
        hasher.update(policy.revision_digest()?.as_bytes());
        hasher.update([0]);
    }
    if let Some(lattice) = &snapshot.lattice {
        hasher.update(lattice.digest()?.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn compile_for_snapshot(
    snapshot: &PolicySnapshot,
    principal: &SimulatedPrincipal,
    kind: &str,
    operation: ObjectSecurityOperation,
    now_ms: i64,
) -> Result<CompiledObjectAccess, String> {
    compile_object_access(PolicyCompileRequest {
        namespace: &snapshot.namespace,
        kind,
        operation,
        context: &principal.context,
        authority: &principal.authority,
        lattice: snapshot.lattice.as_ref(),
        policy: snapshot.policies.get(kind),
        activation_digest: &snapshot.activation_digest,
        purpose: principal.purpose.as_ref(),
        purpose_authorization: principal.purpose_authorization.as_ref(),
        now_ms,
        namespace_granted: principal.namespace_granted,
    })
}

pub fn audit_export_contains_hidden_value(export_json: &[u8], hidden: &str) -> bool {
    String::from_utf8_lossy(export_json).contains(hidden)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::evidence::EvidenceClassification;
    use crate::sekai::markings::{OBJECT_CLASSIFICATION_PROPERTY, PrincipalAuthority};
    use crate::sekai::object_security::{
        OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityPredicate, ObjectSecurityRule, PropertyGrant,
        PropertyGrantAccess, ValueInstanceGrant, value_instance_digest,
    };
    use crate::sekai::purpose_authorization::PURPOSE_AUTHORIZATION_VERSION;
    use std::collections::HashMap;

    fn object(id: &str, owner: &str, state: &str, marking: Option<&str>) -> Object {
        let mut properties = HashMap::from([
            ("owner".into(), owner.into()),
            ("state".into(), state.into()),
            ("secret".into(), format!("hidden-{id}")),
        ]);
        if let Some(marking) = marking {
            properties.insert(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into());
        }
        Object {
            id: id.into(),
            kind: "document".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: format!("doc:{id}"),
            properties,
            created: 1,
            updated: 1,
        }
    }

    fn authority(principal: &str, ceiling: Option<EvidenceClassification>) -> PrincipalAuthority {
        PrincipalAuthority {
            principal: principal.into(),
            classification_ceiling: ceiling,
            classification_token: ceiling.map(|value| value.as_str().into()),
            allowed_purposes: BTreeSet::new(),
        }
    }

    fn context(subjects: &[&str], scopes: &[&str]) -> PrincipalPolicyContext {
        PrincipalPolicyContext {
            subjects: subjects.iter().map(|value| (*value).to_string()).collect(),
            scopes: scopes.iter().map(|value| (*value).to_string()).collect(),
        }
        .normalized()
    }

    fn policy_allow_all() -> ObjectSecurityPolicy {
        ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "document".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: None,
            value_instance_grants: None,
            required_purpose: None,
        }
        .prepare()
        .unwrap()
    }

    fn policy_owner_read() -> ObjectSecurityPolicy {
        ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "document".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                    property: "owner".into(),
                }],
            }],
            property_grants: Some(vec![
                PropertyGrant {
                    property: "owner".into(),
                    access: PropertyGrantAccess::Read,
                },
                PropertyGrant {
                    property: "state".into(),
                    access: PropertyGrantAccess::Read,
                },
            ]),
            value_instance_grants: None,
            required_purpose: None,
        }
        .prepare()
        .unwrap()
    }

    fn compile_for(
        policy: Option<&ObjectSecurityPolicy>,
        ctx: &PrincipalPolicyContext,
        auth: &PrincipalAuthority,
        purpose: Option<&PurposePresentation>,
        authorization: Option<&PurposeAuthorization>,
        granted: bool,
    ) -> CompiledObjectAccess {
        compile_object_access(PolicyCompileRequest {
            namespace: "acme",
            kind: "document",
            operation: ObjectSecurityOperation::Read,
            context: ctx,
            authority: auth,
            lattice: None,
            policy,
            activation_digest: "act",
            purpose,
            purpose_authorization: authorization,
            now_ms: 50,
            namespace_granted: granted,
        })
        .unwrap()
    }

    #[test]
    fn compile_matches_legacy_oracle_on_ten_thousand_cases() {
        let mut seed = 0x885u64;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            seed
        };
        let pick = |next: &mut dyn FnMut() -> u64, n: usize| (next() as usize) % n;
        let mut diverged = 0usize;
        for index in 0..10_000 {
            let owners = ["alice", "bob", "carol"];
            let states = ["open", "closed"];
            let markings = [None, Some("public"), Some("restricted")];
            let owner = owners[pick(&mut next, owners.len())];
            let state = states[pick(&mut next, states.len())];
            let marking = markings[pick(&mut next, markings.len())];
            let obj = object(&format!("o{index}"), owner, state, marking);
            let subject = owners[pick(&mut next, owners.len())];
            let ctx = context(&[subject], &["documents:read", "other"]);
            let ceiling = match pick(&mut next, 3) {
                0 => None,
                1 => Some(EvidenceClassification::Public),
                _ => Some(EvidenceClassification::Restricted),
            };
            let auth = authority(subject, ceiling);
            let granted = pick(&mut next, 5) != 0;
            let policy_kind = pick(&mut next, 5);
            let mut policy = match policy_kind {
                0 => None,
                1 => Some(policy_allow_all()),
                2 => Some(policy_owner_read()),
                3 => {
                    let mut policy = policy_allow_all();
                    policy.required_purpose = Some("review".into());
                    Some(policy.prepare().unwrap())
                }
                _ => {
                    let mut policy = policy_allow_all();
                    policy.value_instance_grants = Some(vec![ValueInstanceGrant {
                        object_id: obj.id.clone(),
                        property: "secret".into(),
                        value_digest: value_instance_digest(&format!("hidden-o{index}")).unwrap(),
                        access: PropertyGrantAccess::Read,
                    }]);
                    Some(policy.prepare().unwrap())
                }
            };
            let mut purpose = None;
            let mut authorization = None;
            if policy
                .as_ref()
                .and_then(|item| item.required_purpose.as_deref())
                == Some("review")
            {
                if pick(&mut next, 2) == 0 {
                    purpose = Some(PurposePresentation {
                        actor: subject.into(),
                        purpose: "review".into(),
                    });
                    authorization = Some(PurposeAuthorization {
                        contract_version: PURPOSE_AUTHORIZATION_VERSION.into(),
                        authorization_id: format!("p{index}"),
                        actor: subject.into(),
                        purpose: "review".into(),
                        namespace: "acme".into(),
                        kind: "document".into(),
                        not_before_ms: 0,
                        not_after_ms: 100,
                        policy_activation_digest: "act".into(),
                        created_by: "root".into(),
                        created_at_ms: 1,
                        revoked_at_ms: 0,
                    });
                } else {
                    purpose = Some(PurposePresentation {
                        actor: subject.into(),
                        purpose: String::new(),
                    });
                }
            }
            if let Some(item) = policy.as_mut()
                && pick(&mut next, 4) == 0
            {
                item.property_grants = Some(vec![PropertyGrant {
                    property: "owner".into(),
                    access: PropertyGrantAccess::Read,
                }]);
            }
            let request = PolicyCompileRequest {
                namespace: "acme",
                kind: "document",
                operation: ObjectSecurityOperation::Read,
                context: &ctx,
                authority: &auth,
                lattice: None,
                policy: policy.as_ref(),
                activation_digest: "act",
                purpose: purpose.as_ref(),
                purpose_authorization: authorization.as_ref(),
                now_ms: 50,
                namespace_granted: granted,
            };
            let compiled = compile_object_access(request.clone()).unwrap();
            let product = compiled.decide(&obj);
            let product_props = compiled.visible_property_names(&obj);
            let (legacy, legacy_props) = evaluate_legacy_layers(request, &obj).unwrap();
            if product.outcome != legacy.outcome
                || product.denied_by != legacy.denied_by
                || product_props != legacy_props
            {
                diverged += 1;
            }
            assert!(
                !audit_export_contains_hidden_value(
                    &product.export_json().unwrap(),
                    &format!("hidden-o{index}")
                ),
                "decision export leaked a hidden value"
            );
        }
        assert_eq!(diverged, 0, "compile diverged from the legacy oracle");
    }

    #[test]
    fn simulation_reports_object_and_property_diffs_and_apply_matches() {
        let alice = SimulatedPrincipal {
            principal: "alice".into(),
            context: context(&["alice"], &[]),
            authority: authority("alice", Some(EvidenceClassification::Public)),
            purpose: None,
            purpose_authorization: None,
            namespace_granted: true,
        };
        let bob = SimulatedPrincipal {
            principal: "bob".into(),
            context: context(&["bob"], &[]),
            authority: authority("bob", Some(EvidenceClassification::Public)),
            purpose: None,
            purpose_authorization: None,
            namespace_granted: true,
        };
        let objects = vec![
            object("doc-a", "alice", "open", None),
            object("doc-b", "bob", "open", None),
        ];
        let current = PolicySnapshot {
            namespace: "acme".into(),
            activation_digest: "current".into(),
            policies: BTreeMap::from([("document".into(), policy_allow_all())]),
            lattice: None,
        };
        let candidate = PolicySnapshot {
            namespace: "acme".into(),
            activation_digest: "candidate".into(),
            policies: BTreeMap::from([("document".into(), policy_owner_read())]),
            lattice: None,
        };
        let report = simulate_policy_change(
            &objects,
            &[alice.clone(), bob.clone()],
            &current,
            &candidate,
            ObjectSecurityOperation::Read,
            50,
        )
        .unwrap();
        assert!(
            report.differences.iter().any(|diff| {
                diff.principal == "alice"
                    && diff.object_id == "doc-b"
                    && diff.property.is_empty()
                    && diff.current_outcome == PolicyOutcome::Allow
                    && diff.candidate_outcome == PolicyOutcome::Deny
            }),
            "alice must lose doc-b: {report:?}"
        );
        assert!(
            report.differences.iter().any(|diff| {
                diff.principal == "alice"
                    && diff.object_id == "doc-a"
                    && diff.property == "secret"
                    && diff.current_outcome == PolicyOutcome::Allow
                    && diff.candidate_outcome == PolicyOutcome::Deny
            }),
            "alice must lose the secret property on doc-a: {report:?}"
        );
        let applied = simulate_policy_change(
            &objects,
            &[alice, bob],
            &candidate,
            &candidate,
            ObjectSecurityOperation::Read,
            50,
        )
        .unwrap();
        assert!(
            applied.differences.is_empty(),
            "applying the candidate must match the simulation residual"
        );
        let export = serde_json::to_vec(&report).unwrap();
        assert!(!audit_export_contains_hidden_value(&export, "hidden-doc-a"));
        assert!(!audit_export_contains_hidden_value(&export, "hidden-doc-b"));
    }

    #[test]
    fn compile_denies_marking_before_row_rules() {
        let obj = object("doc-m", "alice", "open", Some("restricted"));
        let ctx = context(&["alice"], &[]);
        let auth = authority("alice", Some(EvidenceClassification::Public));
        let policy = policy_allow_all();
        let compiled = compile_for(Some(&policy), &ctx, &auth, None, None, true);
        let decision = compiled.decide(&obj);
        assert_eq!(decision.outcome, PolicyOutcome::Deny);
        assert_eq!(decision.denied_by, Some(PolicyLayer::Marking));
    }

    #[test]
    fn unactivated_namespace_allows_when_unmarked_and_granted() {
        let obj = object("doc-u", "alice", "open", None);
        let ctx = context(&["alice"], &[]);
        let auth = authority("alice", None);
        let compiled = compile_for(None, &ctx, &auth, None, None, true);
        assert_eq!(compiled.decide(&obj).outcome, PolicyOutcome::Allow);
        assert_eq!(
            compiled.visible_property_names(&obj).len(),
            obj.properties.len()
        );
    }
}
