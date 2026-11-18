//! `SimulateObjectPolicyChange` with candidate grants (#2304): each simulated
//! change answers what single-object reads give once the change is really
//! made, on SQLite and PostgreSQL.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

const NS: &str = "logistics";
const READER: &str = "j.novak";

fn service_on(db: RuntimeDb) -> SekaiServiceImpl {
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
        db,
    )))
}

/// Run on a scratch PostgreSQL database, on a multi-thread runtime because
/// the PostgreSQL store blocks in place. The store drops after the runtime.
fn on_postgres<F: std::future::Future<Output = ()>>(test: impl FnOnce(RuntimeDb) -> F) {
    let scratch = crate::db::ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test(db.clone()));
    drop(db);
}

fn object(id: &str, kind: &str, properties: &[(&str, &str)]) -> domain::Object {
    domain::Object {
        id: id.into(),
        kind: kind.into(),
        name: id.into(),
        namespace: NS.into(),
        external_id: id.into(),
        properties: properties
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect(),
        created: 1,
        updated: 1,
    }
}

async fn create_grant(
    svc: &SekaiServiceImpl,
    object_id: &str,
    principal: &str,
    role: &str,
) -> String {
    svc.create_grant(with_named_principal(
        CreateGrantRequest {
            grant: Some(Grant {
                id: format!("grant-{object_id}-{principal}"),
                object_id: object_id.into(),
                principal: principal.into(),
                role: role.into(),
                ..Default::default()
            }),
        },
        "local",
    ))
    .await
    .unwrap()
    .into_inner()
    .grant
    .unwrap()
    .id
}

async fn delete_grant(svc: &SekaiServiceImpl, id: &str) {
    svc.delete_grant(with_named_principal(
        DeleteGrantRequest { id: id.into() },
        "local",
    ))
    .await
    .unwrap();
}

async fn grant_id(svc: &SekaiServiceImpl, object_id: &str, principal: &str) -> String {
    svc.db
        .runtime()
        .list_grants(object_id)
        .unwrap()
        .into_iter()
        .find(|grant| grant.principal == principal)
        .unwrap()
        .id
}

/// Objects of `NS` the reader gets through `GetObject`, by kind, over the
/// objects root may read (the simulation's caller).
async fn real_reads(svc: &SekaiServiceImpl) -> BTreeMap<String, u64> {
    let listed = svc
        .list_objects(with_named_principal(
            ListObjectsRequest {
                filter: Some(ListFilter {
                    namespace: NS.into(),
                    limit: 1000,
                    ..Default::default()
                }),
                page_token: String::new(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .objects;
    let mut readable = BTreeMap::new();
    for listed in listed {
        let read = svc
            .get_object(with_named_principal(
                GetObjectRequest {
                    id: listed.id.clone(),
                },
                READER,
            ))
            .await;
        *readable.entry(listed.kind).or_insert(0) += u64::from(read.is_ok());
    }
    readable
}

async fn simulate(
    svc: &SekaiServiceImpl,
    request: SimulateObjectPolicyChangeRequest,
) -> SimulateObjectPolicyChangeResponse {
    svc.simulate_object_policy_change(with_named_principal(
        SimulateObjectPolicyChangeRequest {
            namespace: NS.into(),
            principals: vec![READER.into()],
            ..request
        },
        "root",
    ))
    .await
    .unwrap()
    .into_inner()
}

fn counts(
    response: &SimulateObjectPolicyChangeResponse,
    side: fn(&PolicySimulationKindSummary) -> u64,
) -> BTreeMap<String, u64> {
    response
        .kind_summaries
        .iter()
        .map(|summary| (summary.object_kind.clone(), side(summary)))
        .collect()
}

fn changed_kinds(response: &SimulateObjectPolicyChangeResponse) -> BTreeSet<String> {
    response
        .differences
        .iter()
        .map(|difference| difference.object_kind.clone())
        .collect()
}

fn candidate(object_id: &str, principal: &str, role: &str) -> CandidateGrant {
    CandidateGrant {
        object_id: object_id.into(),
        principal: principal.into(),
        role: role.into(),
        not_after_ms: 0,
    }
}

async fn exercise_grant_simulation(db: RuntimeDb) {
    let svc = service_on(db);
    let runtime = svc.db.runtime();
    // A team-managed namespace, and a reader who is a team principal of
    // another namespace, so the membership gate applies to every read path.
    for (namespace, principal) in [(NS, "owner"), ("novak-home", READER)] {
        let (_, grants) = runtime
            .ensure_team_namespace(namespace, principal, security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
    }
    let boundary = runtime.find_namespace_boundary(NS).unwrap().unwrap().id;
    for candidate in [
        object("s1", "Shipment", &[("region", "eu"), ("weight_kg", "4")]),
        object("s2", "Shipment", &[("region", "eu"), ("weight_kg", "9")]),
        object("s3", "Shipment", &[("region", "us"), ("weight_kg", "2")]),
        object("s4", "Shipment", &[("region", "eu"), ("weight_kg", "1")]),
        object("s5", "Shipment", &[("region", "eu"), ("weight_kg", "7")]),
        object("c1", "Customer", &[("tier", "gold")]),
        object("c2", "Customer", &[("tier", "silver")]),
        object(
            "c3",
            "Customer",
            &[("tier", "gold"), ("access_marking", "restricted")],
        ),
    ] {
        runtime.create_object(&candidate).unwrap();
    }
    // s4 is shared by root and the reader; s5 only by the reader, so the
    // root caller may not read it and the simulation must not count it.
    create_grant(&svc, "s4", "root", "viewer").await;
    create_grant(&svc, "s4", READER, "viewer").await;
    create_grant(&svc, "s5", READER, "viewer").await;
    // The reader's sealed profile clears restricted once an admin grant
    // on it makes it trusted. It lives outside the simulated namespace.
    runtime
        .create_object(&domain::Object {
            id: "profile-novak".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: READER.into(),
            namespace: "profiles".into(),
            external_id: markings::principal_profile_external_id(READER),
            properties: HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                    "restricted".into(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                    "true".into(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    let nothing = real_reads(&svc).await;
    assert!(nothing.values().all(|count| *count == 0), "{nothing:?}");

    // Adding a namespace membership opens the namespace; marking still
    // hides c3, and s5 stays out of the counts.
    let add_member = simulate(
        &svc,
        SimulateObjectPolicyChangeRequest {
            add_grants: vec![candidate(&boundary, READER, "viewer")],
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        add_member.applied_add_grants,
        vec![candidate(&boundary, READER, "viewer")]
    );
    assert_eq!(
        counts(&add_member, |summary| summary.current_readable),
        nothing
    );
    let customer = add_member
        .kind_summaries
        .iter()
        .find(|summary| summary.object_kind == "Customer")
        .unwrap();
    assert_eq!(
        customer.candidate_denied_by,
        HashMap::from([("marking".into(), 1)])
    );
    assert!(
        add_member
            .differences
            .iter()
            .all(|row| row.object_id != "s5")
    );
    let member_grant = create_grant(&svc, &boundary, READER, "viewer").await;
    let member = real_reads(&svc).await;
    assert_eq!(member.get("Shipment"), Some(&4));
    assert_eq!(member.get("Customer"), Some(&2));
    assert_eq!(
        counts(&add_member, |summary| summary.candidate_readable),
        member
    );
    assert!(
        svc.get_object(with_named_principal(
            GetObjectRequest { id: "s5".into() },
            READER
        ))
        .await
        .is_ok(),
        "the reader reads s5, which the caller may not"
    );

    // An admin grant on the profile clears the marking: only Customer opens.
    let clear = simulate(
        &svc,
        SimulateObjectPolicyChangeRequest {
            add_grants: vec![candidate("profile-novak", "local", "admin")],
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        changed_kinds(&clear),
        BTreeSet::from(["Customer".to_string()])
    );
    let profile_grant = create_grant(&svc, "profile-novak", "local", "admin").await;
    let cleared = real_reads(&svc).await;
    assert_eq!(cleared.get("Customer"), Some(&3));
    assert_eq!(
        counts(&clear, |summary| summary.candidate_readable),
        cleared
    );

    // Removing the reader's grant on a shared object takes that object away.
    let s4_grant = grant_id(&svc, "s4", READER).await;
    let remove = simulate(
        &svc,
        SimulateObjectPolicyChangeRequest {
            remove_grant_ids: vec![s4_grant.clone()],
            ..Default::default()
        },
    )
    .await;
    assert_eq!(remove.applied_remove_grant_ids, vec![s4_grant.clone()]);
    assert_eq!(
        remove
            .differences
            .iter()
            .filter(|row| row.property.is_empty())
            .map(|row| (row.object_id.as_str(), row.candidate_outcome.as_str()))
            .collect::<Vec<_>>(),
        [("s4", "deny")]
    );
    delete_grant(&svc, &s4_grant).await;
    let removed = real_reads(&svc).await;
    assert_eq!(removed.get("Shipment"), Some(&3));
    assert_eq!(
        counts(&remove, |summary| summary.candidate_readable),
        removed
    );

    // A candidate policy and a grant removal are evaluated together.
    let eu_only = crate::sekai::object_security::ObjectSecurityPolicy {
        contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: NS.into(),
        kind: "Shipment".into(),
        rules: vec![crate::sekai::object_security::ObjectSecurityRule {
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            predicates: vec![
                crate::sekai::object_security::ObjectSecurityPredicate::PropertyEquals {
                    property: "region".into(),
                    value: "eu".into(),
                },
            ],
        }],
        property_grants: None,
        value_instance_grants: None,
        required_purpose: None,
    };
    let revision = runtime
        .put_object_security_policy(&eu_only, "root", "put-eu", 1)
        .unwrap();
    let together = simulate(
        &svc,
        SimulateObjectPolicyChangeRequest {
            candidate_policies: vec![ObjectSecurityPolicyBinding {
                kind: "Shipment".into(),
                revision_digest: revision.revision_digest.clone(),
            }],
            remove_grant_ids: vec![profile_grant.clone()],
            ..Default::default()
        },
    )
    .await;
    // A row limit truncates the rows, never the counts.
    let truncated = simulate(
        &svc,
        SimulateObjectPolicyChangeRequest {
            candidate_policies: vec![ObjectSecurityPolicyBinding {
                kind: "Shipment".into(),
                revision_digest: revision.revision_digest.clone(),
            }],
            remove_grant_ids: vec![profile_grant.clone()],
            limit: 1,
            ..Default::default()
        },
    )
    .await;
    assert!(!together.differences_truncated);
    assert!(truncated.differences_truncated);
    assert_eq!(truncated.differences.len(), 1);
    assert_eq!(truncated.kind_summaries, together.kind_summaries);
    // Activation binds every kind in the namespace; the others allow all.
    let mut bindings = BTreeMap::from([("Shipment".to_string(), revision.revision_digest)]);
    for kind in real_reads(&svc)
        .await
        .into_keys()
        .filter(|kind| kind != "Shipment")
    {
        let allow_all = crate::sekai::object_security::ObjectSecurityPolicy {
            kind: kind.clone(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            ..eu_only.clone()
        };
        let allowed = runtime
            .put_object_security_policy(&allow_all, "root", &format!("put-{kind}"), 2)
            .unwrap();
        bindings.insert(kind, allowed.revision_digest);
    }
    runtime
        .activate_object_security_policies(NS, &bindings, "root", "activate-eu", 3)
        .unwrap();
    delete_grant(&svc, &profile_grant).await;
    let both = real_reads(&svc).await;
    assert_eq!(both.get("Shipment"), Some(&2), "s1 and s2: eu, s3 is us");
    assert_eq!(both.get("Customer"), Some(&2));
    assert_eq!(
        counts(&together, |summary| summary.candidate_readable),
        both
    );

    // Nothing was changed by any simulation, and each one was recorded.
    let recorded = runtime
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            target_id: Some(NS.into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|decision| decision.action == "simulate_object_policy_change")
        .collect::<Vec<_>>();
    assert_eq!(recorded.len(), 5);
    assert!(recorded.iter().any(|decision| {
        decision.evidence.get("remove_grant_ids") == Some(&s4_grant)
            && decision.evidence.get("principals").map(String::as_str) == Some(READER)
    }));
    assert_eq!(grant_id(&svc, &boundary, READER).await, member_grant);
}

#[tokio::test]
async fn simulated_grant_changes_match_real_reads() {
    exercise_grant_simulation(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_simulated_grant_changes_match_real_reads() {
    on_postgres(exercise_grant_simulation);
}

#[tokio::test]
async fn candidate_grants_stay_inside_the_simulated_namespace() {
    let svc = service_on(RuntimeDb::memory());
    let runtime = svc.db.runtime();
    runtime
        .create_object(&object("s1", "Shipment", &[]))
        .unwrap();
    let mut elsewhere = object("x1", "Shipment", &[]);
    elsewhere.namespace = "elsewhere".into();
    runtime.create_object(&elsewhere).unwrap();
    let outside = svc
        .simulate_object_policy_change(with_named_principal(
            SimulateObjectPolicyChangeRequest {
                namespace: NS.into(),
                principals: vec![READER.into()],
                add_grants: vec![candidate("x1", READER, "viewer")],
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(outside.code(), tonic::Code::NotFound, "{outside}");
    // An object the caller may not read answers like a missing one.
    runtime
        .create_object(&object("private", "Shipment", &[]))
        .unwrap();
    create_grant(&svc, "private", READER, "viewer").await;
    for target in ["private", "missing"] {
        let hidden = svc
            .simulate_object_policy_change(with_named_principal(
                SimulateObjectPolicyChangeRequest {
                    namespace: NS.into(),
                    add_grants: vec![candidate(target, READER, "viewer")],
                    ..Default::default()
                },
                "root",
            ))
            .await
            .unwrap_err();
        assert_eq!(hidden.code(), outside.code(), "{target}: {hidden}");
        assert_eq!(hidden.message(), outside.message(), "{target}");
    }
    let role = svc
        .simulate_object_policy_change(with_named_principal(
            SimulateObjectPolicyChangeRequest {
                namespace: NS.into(),
                add_grants: vec![candidate("s1", READER, "reader")],
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap_err();
    assert_eq!(role.code(), tonic::Code::InvalidArgument, "{role}");
    let not_admin = svc
        .simulate_object_policy_change(with_named_principal(
            SimulateObjectPolicyChangeRequest {
                namespace: NS.into(),
                ..Default::default()
            },
            READER,
        ))
        .await
        .unwrap_err();
    assert_eq!(
        not_admin.code(),
        tonic::Code::PermissionDenied,
        "{not_admin}"
    );
}
