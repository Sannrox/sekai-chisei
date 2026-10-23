//! Isolation probe catalogue (#1620): one probe per past isolation bug.
//!
//! Each entry names a past bypass (cross-tenant or cross-namespace reads,
//! marked values leaking through queries, Actions without permission,
//! delegation abuse, forged or tenant-less credentials), the denial its
//! probe expects, and the tests that replay it. Probes run in-process with
//! no fixed port; where an earlier fix already shipped a regression test at
//! the right layer, that test is the probe, and the probes below fill the
//! gaps against synthetic tenants. `every_catalogued_bug_has_a_probe`
//! refuses an entry whose probe is missing, so the catalogue cannot drift
//! from the suite. Add an entry with every new isolation bug.

use super::*;
use crate::sekai::synthetic::{SizePreset, Spec, SupplyChain, SyntheticPlan, apply, generate};

pub(super) const ISOLATION_PROBE_CATALOGUE_VERSION: &str = "sekai.isolation-probes/v1";

struct Probe {
    bug: u32,
    bypass: &'static str,
    expected_denial: &'static str,
    /// `(source file, test fn)` pairs that replay the bypass.
    tests: &'static [(&'static str, &'static str)],
}

const PROBES_FILE: &str = "src/grpc/isolation_probes.rs";
const SEKAI_TESTS: &str = "src/grpc/sekai_service_tests.rs";
const CHISEI_TESTS: &str = "src/grpc/chisei_service_tests.rs";

const CATALOGUE: &[Probe] = &[
    Probe {
        bug: 929,
        bypass: "insecure transport let the caller pick the tenant of an assertion",
        expected_denial: "Unauthenticated",
        tests: &[(
            "src/grpc/mod.rs",
            "insecure_tcp_interceptor_rejects_assertion_tenant_header",
        )],
    },
    Probe {
        bug: 983,
        bypass: "a leaf-kind property hidden by a property grant leaked through an aggregation",
        expected_denial: "PermissionDenied",
        tests: &[(
            "src/grpc/object_set_query.rs",
            "aggregate_property_fails_closed_when_leaf_grant_denies",
        )],
    },
    Probe {
        bug: 1140,
        bypass: "comma-listed or self-asserted principals satisfied an approver",
        expected_denial: "PermissionDenied",
        tests: &[(
            PROBES_FILE,
            "isolation_probe_1140_only_one_credentialed_subject_decides",
        )],
    },
    Probe {
        bug: 1147,
        bypass: "expand, explain and retrieve traversed a foreign tenant's namespace",
        expected_denial: "PermissionDenied",
        tests: &[(
            SEKAI_TESTS,
            "semantic_reads_apply_the_enterprise_tenant_gate",
        )],
    },
    Probe {
        bug: 1187,
        bypass: "the hosted routing catalog was read before the namespace check",
        expected_denial: "PermissionDenied",
        tests: &[(
            CHISEI_TESTS,
            "hosted_routes_never_fall_back_and_read_the_catalog_only_when_authorized_and_needed",
        )],
    },
    Probe {
        bug: 1203,
        bypass: "link tools read and wrote links on objects outside the session namespace",
        expected_denial: "NotFound",
        tests: &[(
            PROBES_FILE,
            "isolation_probe_1203_link_tools_bind_the_session_namespace",
        )],
    },
    Probe {
        bug: 1341,
        bypass: "a hop-only plane executed on an empty namespace policy",
        expected_denial: "FailedPrecondition",
        tests: &[(
            CHISEI_TESTS,
            "hop_only_chisei_plane_refuses_plan_content_native_and_policy_summary",
        )],
    },
    Probe {
        bug: 1376,
        bypass: "action instance reads exposed pending payloads across tenants and grants",
        expected_denial: "PermissionDenied",
        tests: &[
            (
                SEKAI_TESTS,
                "action_instance_reads_enforce_authenticated_tenant",
            ),
            (
                SEKAI_TESTS,
                "action_instance_reads_require_entitlement_and_target_visibility",
            ),
        ],
    },
    Probe {
        bug: 1382,
        bypass: "document extraction wrote objects without action policy or write check",
        expected_denial: "refused",
        tests: &[(
            "src/sekai/function_document.rs",
            "allowed_extract_is_refused_by_the_write_authorization",
        )],
    },
    Probe {
        bug: 1400,
        bypass: "a tenant-less machine credential passed with a multi-tenant extension loaded",
        expected_denial: "Unauthenticated",
        tests: &[(
            PROBES_FILE,
            "isolation_probe_1400_tenantless_machine_context_is_refused",
        )],
    },
    Probe {
        bug: 1420,
        bypass: "delegated work applied without re-checking the delegator when records were missing",
        expected_denial: "refused",
        tests: &[
            (
                "src/sekai/action_work_lifecycle.rs",
                "apply_refuses_when_action_instance_is_missing",
            ),
            (
                CHISEI_TESTS,
                "execute_plan_stream_refuses_when_planning_receipt_is_missing",
            ),
        ],
    },
    Probe {
        bug: 1513,
        bypass: "an author certified their own agent definition and undid a revoke",
        expected_denial: "PermissionDenied",
        tests: &[(
            SEKAI_TESTS,
            "definition_certification_refuses_self_certify_revoke_undo_and_caller_statuses",
        )],
    },
];

fn source(file: &str) -> &'static str {
    match file {
        "src/grpc/mod.rs" => include_str!("mod.rs"),
        "src/grpc/object_set_query.rs" => include_str!("object_set_query.rs"),
        PROBES_FILE => include_str!("isolation_probes.rs"),
        SEKAI_TESTS => include_str!("sekai_service_tests.rs"),
        CHISEI_TESTS => include_str!("chisei_service_tests.rs"),
        "src/sekai/function_document.rs" => include_str!("../sekai/function_document.rs"),
        "src/sekai/action_work_lifecycle.rs" => include_str!("../sekai/action_work_lifecycle.rs"),
        other => panic!("catalogue names an unknown source file {other}"),
    }
}

#[test]
fn every_catalogued_bug_has_a_probe() {
    assert_eq!(
        ISOLATION_PROBE_CATALOGUE_VERSION,
        "sekai.isolation-probes/v1"
    );
    let mut previous = 0;
    for probe in CATALOGUE {
        assert!(
            probe.bug > previous,
            "catalogue is ordered and unique at #{}",
            probe.bug
        );
        previous = probe.bug;
        assert!(!probe.bypass.is_empty() && !probe.expected_denial.is_empty());
        assert!(!probe.tests.is_empty(), "#{} has no probe", probe.bug);
        for (file, test) in probe.tests {
            let source = source(file);
            let declared = source.find(&format!("fn {test}("));
            assert!(
                declared.is_some(),
                "#{} probe {test} is missing from {file}",
                probe.bug
            );
            // The probe must be a test, not a helper of the same name.
            let before = &source[..declared.unwrap()];
            let attribute = before.rfind("#[").map(|at| &before[at..]).unwrap_or("");
            assert!(
                attribute.contains("test"),
                "#{} probe {test} in {file} is not a test",
                probe.bug
            );
        }
    }
}

/// Two synthetic tenants in one store, served in-process.
fn synthetic_tenants() -> (SekaiServiceImpl, SyntheticPlan, SyntheticPlan) {
    let db = Arc::new(RuntimeDb::memory());
    let tenant = |namespace: &str, seed| {
        generate(
            &SupplyChain,
            &Spec {
                namespace: namespace.into(),
                seed,
                preset: SizePreset::Demo,
            },
        )
        .unwrap()
    };
    let north = tenant("probe-north", 11);
    let south = tenant("probe-south", 12);
    apply(&db, &north).unwrap();
    apply(&db, &south).unwrap();
    let service = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));
    (service, north, south)
}

fn principal_with_role(plan: &SyntheticPlan, role: &str) -> String {
    plan.principals
        .iter()
        .find(|principal| principal.role == role)
        .unwrap()
        .id
        .clone()
}

fn with_credentialed_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = with_named_principal(payload, principal);
    request
        .metadata_mut()
        .insert("x-sekai-auth-source", MetadataValue::from_static("token"));
    request
}

/// #1140: an approval binds to exactly one credentialed subject.
#[tokio::test]
async fn isolation_probe_1140_only_one_credentialed_subject_decides() {
    use crate::sekai::action_instance::STATUS_PARKED;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionRequest,
    };
    let (svc, north, _) = synthetic_tenants();
    let db = svc.db.runtime();
    let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all(&north.namespace);
    policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
    db.upsert_action_policy(&policy).unwrap();
    let action = &north.actions[0];
    let editor = principal_with_role(&north, "editor");
    let admin = principal_with_role(&north, "admin");
    // A revision of the history's Action type that names the tenant admin
    // as its approver.
    let mut approved = north.action_types[0].clone();
    approved.version = "2".into();
    approved.approvers = vec![admin.clone()];
    db.put_governed_action_type(approved, "probe", 1).unwrap();
    let parked = ActionInstanceAdmission::new(db, None)
        .admit(
            ActionInstanceAdmissionRequest {
                namespace: north.namespace.clone(),
                type_id: action.type_id.clone(),
                version: "2".into(),
                parameters_json: serde_json::json!({
                    "object_id": action.object_id,
                    "severity": "high",
                    "state": "triaged",
                })
                .to_string(),
                idempotency_key: "probe-1140".into(),
                evidence_submission_ids: Vec::new(),
                request_id: "probe-1140".into(),
                ontology_digest: String::new(),
                autonomous_envelope_id: String::new(),
                policy_context: Default::default(),
                delegating_actor: None,
                budget_already_reserved: false,
                resource_tenant: String::new(),
                binding_markings: Vec::new(),
                source_object_id: String::new(),
                marking_gate: Default::default(),
                offline: None,
            },
            &editor,
            2_000_000_000_000,
        )
        .unwrap()
        .instance;
    assert_eq!(parked.status, STATUS_PARKED);
    let decide = || DecideActionInstanceRequest {
        instance_id: parked.instance_id.clone(),
        decision: "grant".into(),
        reason: "probe".into(),
    };

    // Comma-listed principals and a self-asserted identity cannot decide.
    for request in [
        with_credentialed_principal(decide(), &format!("mallory,{admin}")),
        with_named_principal(decide(), &admin),
    ] {
        let refused = svc.decide_action_instance(request).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    }
    // Control: the named approver, credentialed, decides.
    let granted = svc
        .decide_action_instance(with_credentialed_principal(decide(), &admin))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(granted.instance.unwrap().status, STATUS_PARKED);
}

/// #1203: the link tools bind object ids to the session namespace, so a
/// cross-namespace grant does not open another tenant's links to them.
#[tokio::test]
async fn isolation_probe_1203_link_tools_bind_the_session_namespace() {
    let (svc, north, south) = synthetic_tenants();
    let viewer = principal_with_role(&north, "viewer");
    // A public object, so clearance is not what refuses.
    let foreign = south
        .objects
        .iter()
        .find(|object| {
            object.properties[crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY] == "public"
        })
        .unwrap();
    // The north viewer holds a grant on a south object, so the object ACL
    // alone admits the read.
    grant_object_role(&svc, &foreign.id, &viewer, security::Role::Viewer);
    let get = || GetLinksRequest {
        object_id: foreign.id.clone(),
        relation: String::new(),
        direction: String::new(),
    };
    svc.get_links(with_named_principal(get(), &viewer))
        .await
        .expect("control: a direct read with the grant is admitted");

    let mut tool = with_named_principal(get(), &viewer);
    tool.metadata_mut().insert(
        "x-sekai-capability",
        MetadataValue::from_static("sekai.links.get"),
    );
    tool.metadata_mut().insert(
        "x-sekai-namespace",
        MetadataValue::try_from(north.namespace.as_str()).unwrap(),
    );
    let refused = svc.get_links(tool).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::NotFound);
}

/// #1400: with a multi-tenant extension loaded, a machine credential that
/// carries no tenant is refused at the RPC, not resolved to some tenant.
#[tokio::test]
async fn isolation_probe_1400_tenantless_machine_context_is_refused() {
    let svc = enterprise_service();
    seed_lineage_object(&svc, "probe-object", "allowed");
    let get = || GetObjectRequest {
        id: "probe-object".into(),
    };
    let mut tenantless = Request::new(get());
    tenantless
        .extensions_mut()
        .insert(crate::enterprise::AuthenticatedContext::machine(
            crate::enterprise::AuthenticatedPrincipal {
                subject: "machine-user".into(),
                credential_id: "machine-credential".into(),
            },
        ));
    let refused = svc.get_object(tenantless).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unauthenticated);
    // Control: the same read with the tenant context passes the gate.
    let admitted = svc.get_object(with_tenant_context(get())).await;
    assert_ne!(
        admitted.err().map(|status| status.code()),
        Some(tonic::Code::Unauthenticated)
    );
}
