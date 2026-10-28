//! Security finding and exposure package (#1923, part of #1668).
//!
//! A types-only domain package built like the feedback package (ADR 0095,
//! ADR 0135): ontology classes, ObjectTypes, and governed Action types for
//! findings, finding occurrences, hypotheses, and exposures. Objects are
//! written only through those Actions. Package rules on top of the
//! ObjectType schema:
//!
//! - A finding is unique per namespace by problem signature. A second report
//!   of the same problem is an occurrence of that finding, not a new one.
//! - An occurrence is unique per namespace by its source occurrence id, so a
//!   replayed observation never counts twice.
//! - A hypothesis is a separate kind and can never be cited as exposure
//!   evidence: an exposure verdict other than `unknown` must cite a measured
//!   occurrence of the same finding.
//! - An exposure is unique per finding and deployed target (release and
//!   environment), and its target identity cannot change.
//!
//! Identities are stamped into `external_id` and enforced at commit by a
//! partial unique index on `(namespace, external_id)` for these kinds; the
//! plan-time checks here only give a precise error.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::capability_package::{
    CapabilityPackageCertification, MEMBER_ACTION_TYPE, MEMBER_EVALUATION, MEMBER_ONTOLOGY,
    PACKAGE_CONTRACT, PackageMember, certification_digest_for, certify_package, package_digest_for,
};
use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
use crate::sekai::schema::{
    ObjectType, PropertyDef, PropertyType, default_property_classification,
};

pub const PACKAGE_ID: &str = "pkg:security.finding-exposure/v1";
pub const PACKAGE_VERSION: &str = "1";
pub const CERTIFICATION_ID: &str = "cert:security.finding-exposure/v1";
pub const KIND_FINDING: &str = "security_finding";
pub const KIND_OCCURRENCE: &str = "security_finding_occurrence";
pub const KIND_HYPOTHESIS: &str = "security_hypothesis";
pub const KIND_EXPOSURE: &str = "security_exposure";
pub const ACTION_FINDING: &str = "security.finding.record";
pub const ACTION_OCCURRENCE: &str = "security.occurrence.record";
pub const ACTION_HYPOTHESIS: &str = "security.hypothesis.record";
pub const ACTION_EXPOSURE: &str = "security.exposure.record";
pub const ACTION_EXPOSURE_VERDICT: &str = "security.exposure.verdict";
pub const VERDICT_UNKNOWN: &str = "unknown";

pub const ONTOLOGY_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/security/ontology-v1.json"
));
pub const DOMAIN_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/security/domain-v1.json"
));
pub const ACTION_TYPES_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/security/action-types-v1.json"
));
pub const EVALUATION_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/security/evaluation-v1.json"
));

const MEMBER_ONTOLOGY_ID: &str = "security.ontology/v1";
const MEMBER_ACTION_ID: &str = "security.actions/v1";
const MEMBER_EVALUATION_ID: &str = "security.evaluation/v1";

#[derive(Deserialize)]
struct DomainDocument {
    classes: Vec<DomainClass>,
}

#[derive(Deserialize)]
struct DomainClass {
    mapped_kind: String,
    #[serde(default)]
    kind_description: String,
    #[serde(default)]
    properties: Vec<DomainProperty>,
}

#[derive(Deserialize)]
struct DomainProperty {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    description: String,
    #[serde(default)]
    enum_values: Vec<String>,
}

#[derive(Deserialize)]
struct ActionTypesDocument {
    actions: Vec<ActionTypeFixture>,
}

#[derive(Deserialize)]
struct ActionTypeFixture {
    type_id: String,
    description: String,
    object_kind: String,
    object_mutation: String,
    parameter_schema: serde_json::Value,
}

/// Register package ObjectTypes and Action types, then certify the ontology,
/// action-type, and evaluation members.
pub fn install(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<CapabilityPackageCertification, String> {
    register_object_types(db)?;
    register_action_types(db, namespace, actor, now_ms)?;
    certify(db, namespace, actor, now_ms)
}

fn register_object_types(db: &RuntimeDb) -> Result<(), String> {
    let document: DomainDocument = serde_json::from_str(DOMAIN_JSON)
        .map_err(|error| format!("security domain fixture: {error}"))?;
    for class in document.classes {
        db.upsert_object_type(&ObjectType {
            kind: class.mapped_kind,
            description: class.kind_description,
            properties: class
                .properties
                .iter()
                .map(object_property)
                .collect::<Result<Vec<_>, _>>()?,
            is_builtin: false,
            implements: Vec::new(),
        })?;
    }
    Ok(())
}

fn object_property(property: &DomainProperty) -> Result<PropertyDef, String> {
    let prop_type = PropertyType::parse(&property.value_type).ok_or_else(|| {
        format!(
            "unknown security property type {} for {}",
            property.value_type, property.name
        )
    })?;
    Ok(PropertyDef {
        name: property.name.clone(),
        prop_type,
        required: property.required,
        description: property.description.clone(),
        enum_values: property.enum_values.clone(),
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: default_property_classification(),
        struct_fields: Vec::new(),
    })
}

fn register_action_types(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    let document: ActionTypesDocument = serde_json::from_str(ACTION_TYPES_JSON)
        .map_err(|error| format!("security action-types fixture: {error}"))?;
    for action in document.actions {
        let parameter_schema_json = serde_json::to_string(&action.parameter_schema)
            .map_err(|error| format!("security action parameter schema: {error}"))?;
        db.put_governed_action_type(
            GovernedActionType {
                namespace: namespace.into(),
                type_id: action.type_id,
                version: PACKAGE_VERSION.into(),
                description: action.description,
                parameter_schema_json,
                allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                object_kind: action.object_kind,
                object_mutation: action.object_mutation,
                enabled: true,
                ..Default::default()
            },
            actor,
            now_ms,
        )?;
    }
    Ok(())
}

fn certify(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<CapabilityPackageCertification, String> {
    let mut members = vec![
        PackageMember {
            kind: MEMBER_ONTOLOGY.into(),
            member_id: MEMBER_ONTOLOGY_ID.into(),
            digest: fixture_digest(ONTOLOGY_JSON.as_bytes()),
        },
        PackageMember {
            kind: MEMBER_ACTION_TYPE.into(),
            member_id: MEMBER_ACTION_ID.into(),
            digest: fixture_digest(ACTION_TYPES_JSON.as_bytes()),
        },
        PackageMember {
            kind: MEMBER_EVALUATION.into(),
            member_id: MEMBER_EVALUATION_ID.into(),
            digest: fixture_digest(EVALUATION_JSON.as_bytes()),
        },
    ];
    members.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.member_id.cmp(&right.member_id))
    });
    let compatibility = vec![
        "sekai.governed-action/v1".into(),
        "sekai.ontology-product/v1".into(),
    ];
    let package_digest = package_digest_for(PACKAGE_ID, &members, &compatibility)?;
    let mut certification = CapabilityPackageCertification {
        contract_version: PACKAGE_CONTRACT.into(),
        certification_id: CERTIFICATION_ID.into(),
        namespace: namespace.into(),
        owner: actor.into(),
        package_id: PACKAGE_ID.into(),
        package_digest: package_digest.clone(),
        signer_id: actor.into(),
        signer_digest: fixture_digest(actor.as_bytes()),
        members,
        compatibility,
        test_suite_digest: fixture_digest(b"security-package-suite/v1"),
        test_result_digest: fixture_digest(b"security-package-pass/v1"),
        revocation: String::new(),
        revocation_reason: String::new(),
        revoked_at_ms: 0,
        predecessor_id: String::new(),
        superseded_by: String::new(),
        certification_digest: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    };
    certification.certification_digest = certification_digest_for(&certification, &package_digest)?;
    certify_package(db, actor, &certification, now_ms)
}

fn fixture_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Package write rules on top of the ObjectType schema. Stamps each kind's
/// identity into `external_id` and checks references to other package
/// objects. Other kinds pass through.
pub fn validate_object_write(db: &RuntimeDb, object: &mut Object) -> Result<(), String> {
    let identity = match object.kind.as_str() {
        KIND_FINDING => format!("finding:{}", required(object, "problem_signature")?),
        KIND_OCCURRENCE => {
            require_finding(db, object)?;
            format!("occurrence:{}", required(object, "occurrence_id")?)
        }
        KIND_HYPOTHESIS => {
            require_finding(db, object)?;
            return Ok(());
        }
        KIND_EXPOSURE => {
            require_finding(db, object)?;
            validate_exposure_evidence(db, object)?;
            exposure_identity(object)?
        }
        _ => return Ok(()),
    };
    if !object.external_id.is_empty() && object.external_id != identity {
        return Err(format!("{} identity cannot change", object.kind));
    }
    // Only the same kind conflicts, matching the partial unique index:
    // another kind may hold the same external_id.
    for existing in db.find_all_by_external_id(&identity)? {
        if existing.namespace == object.namespace
            && existing.kind == object.kind
            && existing.id != object.id
        {
            return Err(duplicate_message(object, &existing));
        }
    }
    object.external_id = identity;
    Ok(())
}

fn required<'a>(object: &'a Object, property: &str) -> Result<&'a str, String> {
    object
        .properties
        .get(property)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{property} is required"))
}

fn duplicate_message(object: &Object, existing: &Object) -> String {
    match object.kind.as_str() {
        KIND_FINDING => format!(
            "a finding with this problem signature already exists as {}; record an occurrence on it",
            existing.id
        ),
        KIND_OCCURRENCE => format!(
            "occurrence is already recorded as {}; a replayed observation is not a new occurrence",
            existing.id
        ),
        _ => format!(
            "an exposure for this finding and target already exists as {}",
            existing.id
        ),
    }
}

/// The referenced finding exists in the same namespace.
fn require_finding(db: &RuntimeDb, object: &Object) -> Result<Object, String> {
    let finding_id = required(object, "finding_id")?;
    let finding = db
        .get_object(finding_id)?
        .filter(|finding| finding.namespace == object.namespace && finding.kind == KIND_FINDING)
        .ok_or_else(|| format!("finding {finding_id} not found in this namespace"))?;
    Ok(finding)
}

/// One exposure per finding and deployed target. The digest keeps the
/// identity unambiguous whatever the release and environment names contain.
fn exposure_identity(object: &Object) -> Result<String, String> {
    let target = serde_json::to_vec(&[
        required(object, "finding_id")?,
        required(object, "release")?,
        required(object, "environment")?,
    ])
    .map_err(|error| error.to_string())?;
    Ok(format!("exposure:{:x}", Sha256::digest(target)))
}

/// A verdict other than `unknown` must rely on a measured occurrence of the
/// same finding. A hypothesis is never measured evidence.
fn validate_exposure_evidence(db: &RuntimeDb, object: &Object) -> Result<(), String> {
    if required(object, "verdict")? == VERDICT_UNKNOWN {
        return Ok(());
    }
    let evidence_id = required(object, "evidence_id")
        .map_err(|_| "an exposure verdict other than unknown needs evidence_id".to_string())?;
    let evidence = db
        .get_object(evidence_id)?
        .filter(|evidence| evidence.namespace == object.namespace)
        .ok_or_else(|| format!("evidence {evidence_id} not found in this namespace"))?;
    match evidence.kind.as_str() {
        KIND_OCCURRENCE => {}
        KIND_HYPOTHESIS => {
            return Err(format!(
                "evidence {evidence_id} is a hypothesis, not a measured fact"
            ));
        }
        other => {
            return Err(format!(
                "evidence {evidence_id} is a {other}, not a finding occurrence"
            ));
        }
    }
    if evidence.properties.get("finding_id") != object.properties.get("finding_id") {
        return Err(format!(
            "evidence {evidence_id} is an occurrence of a different finding"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
    };
    use crate::sekai::capability_package::{get_package, verify_package};
    use crate::sekai::object_security::PrincipalPolicyContext;
    use sekai_ontology::{Ontology, SqliteOntology};
    use serde_json::{Value, json};
    use std::sync::{Arc, Barrier};
    use std::thread;

    const NAMESPACE: &str = "ops";
    const ACTOR: &str = "reviewer";
    const ONTOLOGY_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn installed() -> RuntimeDb {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        runtime
    }

    fn request(type_id: &str, parameters: &Value, key: &str) -> ActionInstanceAdmissionRequest {
        ActionInstanceAdmissionRequest {
            namespace: NAMESPACE.into(),
            type_id: type_id.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters.to_string(),
            idempotency_key: key.into(),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: ONTOLOGY_DIGEST.into(),
            autonomous_envelope_id: String::new(),
            policy_context: PrincipalPolicyContext::default(),
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: String::new(),
            offline: None,
        }
    }

    fn admit(
        runtime: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
    ) -> Result<(), ActionInstanceAdmissionError> {
        ActionInstanceAdmission::new(runtime, None)
            .admit(request(type_id, &parameters, key), ACTOR, 2_000)
            .map(|_| ())
    }

    fn finding(object_id: &str, signature: &str) -> Value {
        json!({
            "object_id": object_id,
            "source": "scanner",
            "component": "openssl",
            "version_range": "<3.0.8",
            "problem_signature": signature,
            "reported_severity": "high"
        })
    }

    fn occurrence(object_id: &str, finding_id: &str, occurrence_id: &str) -> Value {
        json!({
            "object_id": object_id,
            "finding_id": finding_id,
            "occurrence_id": occurrence_id,
            "observed_at_ms": 1_500
        })
    }

    fn exposure(object_id: &str, verdict: &str, evidence_id: Option<&str>) -> Value {
        let mut parameters = json!({
            "object_id": object_id,
            "finding_id": "f-1",
            "release": "api@1.4.0",
            "environment": "prod",
            "verdict": verdict
        });
        if let Some(evidence_id) = evidence_id {
            parameters["evidence_id"] = evidence_id.into();
        }
        parameters
    }

    fn failed_precondition(outcome: Result<(), ActionInstanceAdmissionError>) -> String {
        match outcome {
            Err(ActionInstanceAdmissionError::FailedPrecondition(message)) => message,
            other => panic!("expected FailedPrecondition, got {other:?}"),
        }
    }

    #[test]
    fn portable_ontology_imports_with_validation_and_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let mut ontology =
            SqliteOntology::initialize(dir.path().join("security-ontology.db")).unwrap();
        ontology.import_json(ONTOLOGY_JSON).unwrap();
        let issues = ontology.validate().unwrap();
        assert!(issues.is_empty(), "{issues:?}");
        let exported = ontology.export().unwrap();
        assert!(exported.classes.iter().any(|class| {
            class.name == "SecurityHypothesis"
                && class.disjoint_classes.contains(&"FindingOccurrence".into())
                && class.disjoint_classes.contains(&"Exposure".into())
        }));
        for subject in [
            "Finding",
            "FindingOccurrence",
            "SecurityHypothesis",
            "Exposure",
        ] {
            assert!(
                exported
                    .provenance
                    .iter()
                    .any(|record| record.subject == subject && !record.source.is_empty()),
                "{subject}"
            );
        }
    }

    #[test]
    fn package_certifies_ontology_action_and_evaluation_members() {
        let runtime = installed();
        let certified = get_package(&runtime, ACTOR, NAMESPACE, CERTIFICATION_ID).unwrap();
        assert_eq!(certified.package_id, PACKAGE_ID);
        let kinds: Vec<_> = certified
            .members
            .iter()
            .map(|member| member.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            [MEMBER_ACTION_TYPE, MEMBER_EVALUATION, MEMBER_ONTOLOGY]
        );
        verify_package(&runtime, ACTOR, NAMESPACE, CERTIFICATION_ID, &certified).unwrap();
        let verdict = runtime
            .get_object_type(KIND_EXPOSURE)
            .unwrap()
            .expect("exposure kind")
            .properties
            .into_iter()
            .find(|property| property.name == "verdict")
            .expect("verdict");
        assert_eq!(
            verdict.enum_values,
            ["exploitable", "not-reachable", "mitigated", "unknown"]
        );
    }

    #[test]
    fn same_signature_collapses_into_one_finding_with_several_occurrences() {
        let runtime = installed();
        admit(
            &runtime,
            ACTION_FINDING,
            finding("f-1", "CVE-2023-0286"),
            "f-1",
        )
        .unwrap();
        let duplicate = failed_precondition(admit(
            &runtime,
            ACTION_FINDING,
            finding("f-2", "CVE-2023-0286"),
            "f-2",
        ));
        assert!(duplicate.contains("already exists as f-1"), "{duplicate}");
        assert!(runtime.get_object("f-2").unwrap().is_none());
        admit(
            &runtime,
            ACTION_OCCURRENCE,
            occurrence("o-1", "f-1", "scan-1"),
            "o-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_OCCURRENCE,
            occurrence("o-2", "f-1", "scan-2"),
            "o-2",
        )
        .unwrap();
        // A replayed observation under a new request is not a new occurrence.
        let replay = failed_precondition(admit(
            &runtime,
            ACTION_OCCURRENCE,
            occurrence("o-3", "f-1", "scan-1"),
            "o-3",
        ));
        assert!(replay.contains("already recorded as o-1"), "{replay}");
        assert!(runtime.get_object("o-3").unwrap().is_none());
        // Replaying the same request is the Action's idempotent no-op.
        admit(
            &runtime,
            ACTION_OCCURRENCE,
            occurrence("o-1", "f-1", "scan-1"),
            "o-1",
        )
        .unwrap();
        let occurrences: Vec<_> = ["o-1", "o-2"]
            .into_iter()
            .filter_map(|id| runtime.get_object(id).unwrap())
            .collect();
        assert_eq!(occurrences.len(), 2);
        assert!(
            occurrences
                .iter()
                .all(|occurrence| occurrence.properties["finding_id"] == "f-1")
        );
        let stored = runtime.get_object("f-1").unwrap().expect("finding");
        assert_eq!(stored.external_id, "finding:CVE-2023-0286");
    }

    #[test]
    fn another_kind_with_the_same_external_id_does_not_block_a_finding() {
        let runtime = installed();
        runtime
            .create_object_with_audit(
                &Object {
                    id: "src-1".into(),
                    kind: "gadget".into(),
                    name: "src-1".into(),
                    namespace: NAMESPACE.into(),
                    external_id: "finding:sig-1".into(),
                    properties: Default::default(),
                    created: 1,
                    updated: 1,
                },
                ACTOR,
            )
            .unwrap();
        admit(&runtime, ACTION_FINDING, finding("f-1", "sig-1"), "f-1").unwrap();
        assert!(runtime.get_object("f-1").unwrap().is_some());
    }

    #[test]
    fn a_hypothesis_cannot_be_recorded_as_a_measured_fact() {
        let runtime = installed();
        admit(&runtime, ACTION_FINDING, finding("f-1", "sig-1"), "f-1").unwrap();
        admit(
            &runtime,
            ACTION_HYPOTHESIS,
            json!({"object_id": "h-1", "finding_id": "f-1", "statement": "reachable through the proxy"}),
            "h-1",
        )
        .unwrap();
        let refused = failed_precondition(admit(
            &runtime,
            ACTION_EXPOSURE,
            exposure("e-1", "exploitable", Some("h-1")),
            "e-1",
        ));
        assert!(
            refused.contains("is a hypothesis, not a measured fact"),
            "{refused}"
        );
        let missing = failed_precondition(admit(
            &runtime,
            ACTION_EXPOSURE,
            exposure("e-1", "exploitable", None),
            "e-1b",
        ));
        assert!(missing.contains("needs evidence_id"), "{missing}");
        assert!(runtime.get_object("e-1").unwrap().is_none());
        // A hypothesis cannot be passed off as an occurrence either.
        let as_occurrence = failed_precondition(admit(
            &runtime,
            ACTION_EXPOSURE,
            exposure("e-2", "not-reachable", Some("f-1")),
            "e-2",
        ));
        assert!(
            as_occurrence.contains("not a finding occurrence"),
            "{as_occurrence}"
        );
    }

    #[test]
    fn exposure_verdict_cites_a_measured_occurrence_and_keeps_its_target() {
        let runtime = installed();
        admit(&runtime, ACTION_FINDING, finding("f-1", "sig-1"), "f-1").unwrap();
        admit(&runtime, ACTION_FINDING, finding("f-9", "sig-9"), "f-9").unwrap();
        admit(
            &runtime,
            ACTION_OCCURRENCE,
            occurrence("o-1", "f-1", "scan-1"),
            "o-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_OCCURRENCE,
            occurrence("o-9", "f-9", "scan-9"),
            "o-9",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_EXPOSURE,
            exposure("e-1", "unknown", None),
            "e-1",
        )
        .unwrap();
        let other_finding = failed_precondition(admit(
            &runtime,
            ACTION_EXPOSURE_VERDICT,
            json!({"object_id": "e-1", "verdict": "exploitable", "evidence_id": "o-9"}),
            "e-1-v0",
        ));
        assert!(
            other_finding.contains("different finding"),
            "{other_finding}"
        );
        admit(
            &runtime,
            ACTION_EXPOSURE_VERDICT,
            json!({"object_id": "e-1", "verdict": "exploitable", "evidence_id": "o-1"}),
            "e-1-v1",
        )
        .unwrap();
        let stored = runtime.get_object("e-1").unwrap().expect("exposure");
        assert_eq!(stored.properties["verdict"], "exploitable");
        assert!(stored.external_id.starts_with("exposure:"));
        let second = failed_precondition(admit(
            &runtime,
            ACTION_EXPOSURE,
            exposure("e-2", "unknown", None),
            "e-2",
        ));
        assert!(second.contains("already exists as e-1"), "{second}");
    }

    #[test]
    fn store_keeps_identities_unique_without_plan_time() {
        let runtime = RuntimeDb::memory();
        let object = |id: &str, kind: &str, external_id: &str| Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: NAMESPACE.into(),
            external_id: external_id.into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        };
        // Real identities carry a kind prefix, so kinds never collide.
        for kind in [KIND_FINDING, KIND_OCCURRENCE, KIND_EXPOSURE] {
            let identity = format!("{kind}:id-1");
            runtime
                .create_object_with_audit(&object(&format!("{kind}-1"), kind, &identity), ACTOR)
                .unwrap();
            let error = runtime
                .create_object_with_audit(&object(&format!("{kind}-2"), kind, &identity), ACTOR)
                .unwrap_err();
            assert!(
                error.contains("UNIQUE constraint failed")
                    || error.contains("duplicate key value violates unique constraint"),
                "{kind}: {error}"
            );
        }
        // Hypotheses and other kinds are not identity-unique.
        for id in ["h-1", "h-2"] {
            runtime
                .create_object_with_audit(&object(id, KIND_HYPOTHESIS, "id-1"), ACTOR)
                .unwrap();
        }
    }

    #[test]
    fn concurrent_findings_with_one_signature_keep_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let runtime = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(path.to_str().expect("utf-8 path")).expect("file sqlite"),
        )));
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        // Spawn both before joining either: the barrier needs two parties.
        let workers: Vec<_> = ["f-a", "f-b"]
            .into_iter()
            .map(|id| {
                let runtime = Arc::clone(&runtime);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    admit(&runtime, ACTION_FINDING, finding(id, "sig-race"), id)
                })
            })
            .collect();
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect();
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
            1,
            "{outcomes:?}"
        );
        let stored = ["f-a", "f-b"]
            .into_iter()
            .filter_map(|id| runtime.get_object(id).unwrap())
            .count();
        assert_eq!(stored, 1);
    }
}
