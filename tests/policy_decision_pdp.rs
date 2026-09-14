//! Compiling policy decision point, simulation, and audit (#885 / ADR 0076).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::evidence::EvidenceClassification;
use sekai_chisei::sekai::markings::PrincipalAuthority;
use sekai_chisei::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
    ObjectSecurityPredicate, ObjectSecurityRule, PrincipalPolicyContext, PropertyGrant,
    PropertyGrantAccess,
};
use sekai_chisei::sekai::policy_decision::{
    PolicyCompileRequest, PolicyDecisionQuery, PolicyDecisionRecord, PolicyOutcome, PolicySnapshot,
    SimulatedPrincipal, audit_export_contains_hidden_value, compile_object_access,
    simulate_policy_change,
};

fn sqlite() -> RuntimeDb {
    RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()))
}

fn document(id: &str, owner: &str) -> Object {
    Object {
        id: id.into(),
        kind: "document".into(),
        name: id.into(),
        namespace: "acme".into(),
        external_id: format!("doc:{id}"),
        properties: HashMap::from([
            ("owner".into(), owner.into()),
            ("secret".into(), format!("hidden-{id}")),
        ]),
        created: 1,
        updated: 1,
    }
}

fn allow_all() -> ObjectSecurityPolicy {
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
}

fn owner_read() -> ObjectSecurityPolicy {
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
        property_grants: Some(vec![PropertyGrant {
            property: "owner".into(),
            access: PropertyGrantAccess::Read,
        }]),
        value_instance_grants: None,
        required_purpose: None,
    }
}

fn principal(name: &str) -> SimulatedPrincipal {
    SimulatedPrincipal {
        principal: name.into(),
        context: PrincipalPolicyContext {
            subjects: vec![name.into()],
            scopes: Vec::new(),
        }
        .normalized(),
        authority: PrincipalAuthority {
            principal: name.into(),
            classification_ceiling: Some(EvidenceClassification::Public),
            classification_token: Some("public".into()),
            allowed_purposes: Default::default(),
        },
        purpose: None,
        purpose_authorization: None,
        namespace_granted: true,
    }
}

#[test]
fn simulated_policy_change_matches_applied_activation() {
    let db = sqlite();
    let alice_doc = document("doc-a", "alice");
    let bob_doc = document("doc-b", "bob");
    db.create_object(&alice_doc).unwrap();
    db.create_object(&bob_doc).unwrap();

    let broad = db
        .put_object_security_policy(&allow_all(), "root", "put-broad", 1)
        .unwrap();
    let owner = db
        .put_object_security_policy(&owner_read(), "root", "put-owner", 2)
        .unwrap();
    db.activate_object_security_policies(
        "acme",
        &BTreeMap::from([("document".into(), broad.revision_digest.clone())]),
        "root",
        "act-broad",
        3,
    )
    .unwrap();

    let current_policy =
        ObjectSecurityPolicy::from_canonical_input(&broad.canonical_policy_json).unwrap();
    let candidate_policy =
        ObjectSecurityPolicy::from_canonical_input(&owner.canonical_policy_json).unwrap();
    let current = PolicySnapshot {
        namespace: "acme".into(),
        activation_digest: "current".into(),
        policies: BTreeMap::from([("document".into(), current_policy)]),
        lattice: None,
    };
    let candidate = PolicySnapshot {
        namespace: "acme".into(),
        activation_digest: "candidate".into(),
        policies: BTreeMap::from([("document".into(), candidate_policy.clone())]),
        lattice: None,
    };
    let objects = vec![alice_doc.clone(), bob_doc.clone()];
    let principals = [principal("alice"), principal("bob")];
    let report = simulate_policy_change(
        &objects,
        &principals,
        &current,
        &candidate,
        ObjectSecurityOperation::Read,
        10,
    )
    .unwrap();
    assert!(
        report.differences.iter().any(|diff| {
            diff.principal == "alice"
                && diff.object_id == "doc-b"
                && diff.property.is_empty()
                && diff.candidate_outcome == PolicyOutcome::Deny
        }),
        "{report:?}"
    );
    assert!(
        report.differences.iter().any(|diff| {
            diff.principal == "alice"
                && diff.object_id == "doc-a"
                && diff.property == "secret"
                && diff.candidate_outcome == PolicyOutcome::Deny
        }),
        "{report:?}"
    );
    let export = serde_json::to_vec(&report).unwrap();
    assert!(!audit_export_contains_hidden_value(&export, "hidden-doc-a"));
    assert!(!audit_export_contains_hidden_value(&export, "hidden-doc-b"));

    db.activate_object_security_policies(
        "acme",
        &BTreeMap::from([("document".into(), owner.revision_digest)]),
        "root",
        "act-owner",
        4,
    )
    .unwrap();
    let applied = PolicySnapshot {
        namespace: "acme".into(),
        activation_digest: "applied".into(),
        policies: BTreeMap::from([("document".into(), candidate_policy)]),
        lattice: None,
    };
    let after = simulate_policy_change(
        &objects,
        &principals,
        &applied,
        &applied,
        ObjectSecurityOperation::Read,
        10,
    )
    .unwrap();
    assert!(after.differences.is_empty(), "{after:?}");
}

#[test]
fn audit_query_returns_allow_and_deny_without_hidden_values() {
    let db = sqlite();
    let object = document("doc-a", "alice");
    db.create_object(&object).unwrap();
    let policy = db
        .put_object_security_policy(&owner_read(), "root", "put-owner", 1)
        .unwrap();
    db.activate_object_security_policies(
        "acme",
        &BTreeMap::from([("document".into(), policy.revision_digest)]),
        "root",
        "act-owner",
        2,
    )
    .unwrap();
    let live = db
        .active_object_policy("acme", "document")
        .unwrap()
        .unwrap();
    for (name, expected) in [
        ("alice", PolicyOutcome::Allow),
        ("bob", PolicyOutcome::Deny),
    ] {
        let ctx = PrincipalPolicyContext {
            subjects: vec![name.into()],
            scopes: Vec::new(),
        }
        .normalized();
        let authority = PrincipalAuthority {
            principal: name.into(),
            classification_ceiling: Some(EvidenceClassification::Public),
            classification_token: Some("public".into()),
            allowed_purposes: Default::default(),
        };
        let compiled = compile_object_access(PolicyCompileRequest {
            namespace: "acme",
            kind: "document",
            operation: ObjectSecurityOperation::Read,
            context: &ctx,
            authority: &authority,
            lattice: None,
            policy: Some(&live),
            activation_digest: "act",
            purpose: None,
            purpose_authorization: None,
            now_ms: 10,
            namespace_granted: true,
        })
        .unwrap();
        let decision = compiled.decide(&object);
        assert_eq!(decision.outcome, expected);
        db.record_policy_decision(&PolicyDecisionRecord {
            event_id: format!("evt-{name}"),
            decision,
            created_at_ms: 10,
        })
        .unwrap();
    }

    let alice = db
        .query_policy_decisions(&PolicyDecisionQuery {
            namespace: "acme".into(),
            principal: "alice".into(),
            ..PolicyDecisionQuery::default()
        })
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].decision.outcome, PolicyOutcome::Allow);
    assert_eq!(alice[0].decision.object_id, "doc-a");
    assert!(!alice[0].decision.policy_revision_digest.is_empty());
    let export = serde_json::to_vec(&alice).unwrap();
    assert!(!audit_export_contains_hidden_value(&export, "hidden-doc-a"));

    let bob = db
        .query_policy_decisions(&PolicyDecisionQuery {
            namespace: "acme".into(),
            principal: "bob".into(),
            ..PolicyDecisionQuery::default()
        })
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].decision.outcome, PolicyOutcome::Deny);
}
