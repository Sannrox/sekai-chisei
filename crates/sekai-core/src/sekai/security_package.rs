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
//! - A disposition (#1924) decides an exposure and records the validity
//!   basis it relied on. Dispositions are never changed: superseding records
//!   a new one that names the previous, which keeps its history and receipt.
//!   An exposure has one first disposition and each disposition at most one
//!   successor, so its history is a single chain.
//! - Accepting risk on an exposure that touches marked data needs the
//!   disposition marked at least as high as the exposure and every reachable
//!   marking. Admission only admits a caller cleared for the marking it
//!   writes, so a caller without that grant cannot accept the risk.
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
/// The current certification. Dispositions (#1924) changed the certified
/// members, so the package is certified again under a new id that succeeds
/// the first one where a namespace holds it.
pub const CERTIFICATION_ID: &str = "cert:security.finding-exposure/v1.1";
/// Certifications this one succeeds, newest first.
const PREVIOUS_CERTIFICATION_IDS: &[&str] = &["cert:security.finding-exposure/v1"];
pub const KIND_FINDING: &str = "security_finding";
pub const KIND_OCCURRENCE: &str = "security_finding_occurrence";
pub const KIND_HYPOTHESIS: &str = "security_hypothesis";
pub const KIND_EXPOSURE: &str = "security_exposure";
pub const KIND_DISPOSITION: &str = "security_disposition";
pub const ACTION_DISPOSITION_RECORD: &str = "security.disposition.record";
pub const ACTION_DISPOSITION_SUPERSEDE: &str = "security.disposition.supersede";
pub const DISPOSITION_ACCEPT_RISK: &str = "accept-risk";
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
    let certification = certification_for(db, namespace, actor)?;
    certify_package(db, actor, &certification, now_ms)
}

/// The package's current certification, succeeding an earlier live one.
fn certification_for(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
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
    // An earlier live certification of this package is succeeded, not
    // collided with, so an installed namespace upgrades in place.
    // Installing again replays the certification as first committed.
    let mut predecessor_id = db
        .get_capability_package(namespace, CERTIFICATION_ID)?
        .map(|current| current.predecessor_id)
        .unwrap_or_default();
    for previous in PREVIOUS_CERTIFICATION_IDS
        .iter()
        .filter(|_| predecessor_id.is_empty())
    {
        if db
            .get_capability_package(namespace, previous)?
            .is_some_and(|package| {
                package.superseded_by.is_empty() && package.revocation.is_empty()
            })
        {
            predecessor_id = (*previous).to_string();
            break;
        }
    }
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
        predecessor_id,
        superseded_by: String::new(),
        certification_digest: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    };
    certification.certification_digest = certification_digest_for(&certification, &package_digest)?;
    Ok(certification)
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
        KIND_DISPOSITION => {
            // Dispositions are never changed; a new decision supersedes.
            if db.get_object(&object.id)?.is_some() {
                return Err(
                    "a disposition cannot be changed; supersede it with a new disposition".into(),
                );
            }
            let exposure = require_exposure(db, object)?;
            if required(object, "disposition")? == DISPOSITION_ACCEPT_RISK {
                require_marking_for_accepted_risk(db, object, &exposure)?;
            }
            disposition_identity(db, object)?
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
        KIND_DISPOSITION
            if object
                .properties
                .get("supersedes")
                .is_some_and(|id| !id.is_empty()) =>
        {
            format!(
                "that disposition is already superseded by {}; supersede the latest one",
                existing.id
            )
        }
        KIND_DISPOSITION => format!(
            "this exposure already has a disposition {}; supersede it instead",
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

/// The decided exposure exists in the same namespace.
fn require_exposure(db: &RuntimeDb, object: &Object) -> Result<Object, String> {
    let exposure_id = required(object, "exposure_id")?;
    db.get_object(exposure_id)?
        .filter(|exposure| exposure.namespace == object.namespace && exposure.kind == KIND_EXPOSURE)
        .ok_or_else(|| format!("exposure {exposure_id} not found in this namespace"))
}

/// The first disposition of an exposure, or the one successor of a previous
/// disposition of the same exposure. Either is unique, so the history of an
/// exposure's dispositions is one chain.
fn disposition_identity(db: &RuntimeDb, object: &Object) -> Result<String, String> {
    let exposure_id = required(object, "exposure_id")?;
    let Some(previous_id) = object.properties.get("supersedes") else {
        return Ok(format!("disposition:{exposure_id}"));
    };
    // Present but blank is not "no predecessor": a supersede names one.
    if previous_id.trim().is_empty() {
        return Err("supersedes must name the disposition being replaced".into());
    }
    let previous = db
        .get_object(previous_id)?
        .filter(|previous| {
            previous.namespace == object.namespace && previous.kind == KIND_DISPOSITION
        })
        .ok_or_else(|| format!("disposition {previous_id} not found in this namespace"))?;
    if previous.properties.get("exposure_id").map(String::as_str) != Some(exposure_id) {
        return Err(format!(
            "disposition {previous_id} decides a different exposure"
        ));
    }
    Ok(format!("disposition-successor:{previous_id}"))
}

/// Accepting risk needs the disposition marked at least as high as the
/// exposure and every marking of reachable data. The written marking already
/// holds what the Action was admitted under, and admission refused any
/// caller not cleared for it.
fn require_marking_for_accepted_risk(
    db: &RuntimeDb,
    object: &Object,
    exposure: &Object,
) -> Result<(), String> {
    let mut needed: Vec<String> = object
        .properties
        .get("reachable_markings")
        .map(|markings| {
            markings
                .split(',')
                .map(str::trim)
                .filter(|marking| !marking.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if let Some(marking) = crate::sekai::markings::object_marking_token(exposure) {
        needed.push(marking.to_string());
    }
    // A successor never needs less than any disposition before it: every
    // earlier disposition's marking and reachable markings still apply,
    // whatever the caller declares now and whatever lies between.
    let mut previous_id = object
        .properties
        .get("supersedes")
        .filter(|id| !id.trim().is_empty())
        .cloned();
    let mut visited = std::collections::BTreeSet::new();
    while let Some(id) = previous_id.take() {
        if !visited.insert(id.clone()) {
            return Err(format!("disposition chain through {id} loops"));
        }
        let Some(previous) = db.get_object(&id)?.filter(|previous| {
            previous.kind == KIND_DISPOSITION && previous.namespace == object.namespace
        }) else {
            break;
        };
        if let Some(marking) = crate::sekai::markings::object_marking_token(&previous) {
            needed.push(marking.to_string());
        }
        if let Some(markings) = previous.properties.get("reachable_markings") {
            needed.extend(
                markings
                    .split(',')
                    .map(str::trim)
                    .filter(|marking| !marking.is_empty())
                    .map(str::to_string),
            );
        }
        previous_id = previous
            .properties
            .get("supersedes")
            .filter(|id| !id.trim().is_empty())
            .cloned();
    }
    needed.sort();
    needed.dedup();
    if needed.is_empty() {
        return Ok(());
    }
    let lattice = db
        .get_classification_lattice(&object.namespace)?
        .unwrap_or_else(|| {
            crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                &object.namespace,
            )
        });
    let held = crate::sekai::markings::object_marking_token(object).unwrap_or_default();
    let mut uncovered = Vec::new();
    for marking in &needed {
        if held.is_empty() || !lattice.dominates(held, marking)? {
            uncovered.push(marking.as_str());
        }
    }
    if uncovered.is_empty() {
        return Ok(());
    }
    Err(format!(
        "accepting risk on data marked {} needs the disposition marked at least as high as each",
        uncovered.join(", ")
    ))
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

    /// A namespace certified before dispositions existed upgrades: the new
    /// certification succeeds the first instead of colliding with it.
    #[test]
    fn an_earlier_certification_is_succeeded_on_install() {
        let runtime = RuntimeDb::memory();
        let earlier = crate::sekai::capability_package::CapabilityPackageCertification {
            certification_id: PREVIOUS_CERTIFICATION_IDS[0].into(),
            ..certification_for(&runtime, NAMESPACE, ACTOR).unwrap()
        };
        let mut earlier = earlier;
        earlier.members[0].digest = fixture_digest(b"earlier members");
        earlier.package_digest =
            package_digest_for(PACKAGE_ID, &earlier.members, &earlier.compatibility).unwrap();
        earlier.certification_digest =
            certification_digest_for(&earlier, &earlier.package_digest).unwrap();
        certify_package(&runtime, ACTOR, &earlier, 500).unwrap();

        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        let current = get_package(&runtime, ACTOR, NAMESPACE, CERTIFICATION_ID).unwrap();
        assert_eq!(current.predecessor_id, PREVIOUS_CERTIFICATION_IDS[0]);
        let previous =
            get_package(&runtime, ACTOR, NAMESPACE, PREVIOUS_CERTIFICATION_IDS[0]).unwrap();
        assert_eq!(previous.superseded_by, CERTIFICATION_ID);
        // Installing again is a replay.
        install(&runtime, NAMESPACE, ACTOR, 2_000).unwrap();
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

    fn with_exposure() -> RuntimeDb {
        let runtime = installed();
        admit(&runtime, ACTION_FINDING, finding("f-1", "sig-1"), "f").unwrap();
        admit(
            &runtime,
            ACTION_EXPOSURE,
            exposure("e-1", VERDICT_UNKNOWN, None),
            "e",
        )
        .unwrap();
        runtime
    }

    fn disposition(object_id: &str, decision: &str, supersedes: Option<&str>) -> Value {
        let mut parameters = json!({
            "object_id": object_id,
            "exposure_id": "e-1",
            "disposition": decision,
            "dependency_closure_digest": "sha256:closure",
            "release_digest": "sha256:release",
            "configuration_digest": "sha256:config",
            "advisory_revision": "GHSA-1:3",
            "expires_at_ms": 9_000
        });
        if let Some(previous) = supersedes {
            parameters["supersedes"] = previous.into();
        }
        parameters
    }

    /// Admit as a caller cleared only up to `ceiling` on the default lattice.
    fn admit_cleared(
        runtime: &RuntimeDb,
        type_id: &str,
        parameters: Value,
        key: &str,
        ceiling: &'static str,
    ) -> Result<(), ActionInstanceAdmissionError> {
        let mut admission = request(type_id, &parameters, key);
        admission.marking_gate = crate::sekai::action_instance_admission::MarkingGate::new(
            move |marking| {
                crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                    NAMESPACE,
                )
                .dominates(ceiling, marking)
            },
        );
        ActionInstanceAdmission::new(runtime, None)
            .admit(admission, ACTOR, 2_000)
            .map(|_| ())
    }

    /// Accepting risk on an exposure that reaches marked data needs the
    /// disposition marked that high, and only a caller cleared for that
    /// marking is admitted (#1924).
    #[test]
    fn accepting_risk_on_marked_data_needs_the_grant_for_that_marking() {
        let runtime = with_exposure();
        let mut accept = disposition("d-1", DISPOSITION_ACCEPT_RISK, None);
        accept["reachable_markings"] = "internal, confidential".into();
        let message = failed_precondition(admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            accept.clone(),
            "d1",
        ));
        assert!(message.contains("confidential, internal"), "{message}");

        accept["access_marking"] = "confidential".into();
        let denied = admit_cleared(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            accept.clone(),
            "d1b",
            "internal",
        );
        assert!(
            matches!(
                denied,
                Err(ActionInstanceAdmissionError::PermissionDenied(_))
            ),
            "{denied:?}"
        );
        assert!(runtime.get_object("d-1").unwrap().is_none());

        admit_cleared(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            accept,
            "d1c",
            "confidential",
        )
        .unwrap();

        // A successor needs what the disposition it replaces needed, even if
        // the caller declares no reachable markings now.
        let mut lower = disposition("d-2", DISPOSITION_ACCEPT_RISK, Some("d-1"));
        lower["access_marking"] = "internal".into();
        let message = failed_precondition(admit_cleared(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            lower,
            "d2",
            "internal",
        ));
        assert!(message.contains("confidential"), "{message}");

        // The requirement survives a non-risk disposition in between.
        admit(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            disposition("d-2", "fixed", Some("d-1")),
            "d2-fixed",
        )
        .unwrap();
        let message = failed_precondition(admit_cleared(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            disposition("d-3", DISPOSITION_ACCEPT_RISK, Some("d-2")),
            "d3",
            "internal",
        ));
        assert!(message.contains("confidential"), "{message}");

        // A recorded disposition is never changed in place.
        let mut changed = runtime.get_object("d-1").unwrap().unwrap();
        changed
            .properties
            .insert("disposition".into(), "fixed".into());
        let message = validate_object_write(&runtime, &mut changed).unwrap_err();
        assert!(message.contains("cannot be changed"), "{message}");
        let message = failed_precondition(admit(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            disposition("d-9", "fixed", Some(" ")),
            "d9",
        ));
        assert!(message.contains("supersedes must name"), "{message}");
        let recorded = runtime.get_object("d-1").unwrap().unwrap();
        assert_eq!(recorded.external_id, "disposition:e-1");
        assert_eq!(recorded.properties["release_digest"], "sha256:release");
    }

    /// Superseding records a new disposition and keeps the previous one with
    /// its receipt. An exposure's dispositions form one chain.
    #[test]
    fn a_superseded_disposition_keeps_its_history_and_the_chain_is_single() {
        let runtime = with_exposure();
        let operation_id = ActionInstanceAdmission::new(&runtime, None)
            .admit(
                request(
                    ACTION_DISPOSITION_RECORD,
                    &disposition("d-1", "false-positive", None),
                    "d1",
                ),
                ACTOR,
                2_000,
            )
            .unwrap()
            .instance
            .operation_id;
        let first = runtime.get_object("d-1").unwrap().unwrap();
        let message = failed_precondition(admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-x", "fixed", None),
            "dx",
        ));
        assert!(message.contains("supersede it instead"), "{message}");

        admit(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            disposition("d-2", "fixed", Some("d-1")),
            "d2",
        )
        .unwrap();
        let kept = runtime.get_object("d-1").unwrap().unwrap();
        assert_eq!(
            (kept.properties, kept.updated, kept.external_id),
            (first.properties, first.updated, first.external_id)
        );
        assert_eq!(
            runtime.get_object("d-2").unwrap().unwrap().external_id,
            "disposition-successor:d-1"
        );
        assert!(
            runtime
                .get_operation_receipt(&operation_id)
                .unwrap()
                .is_some()
        );

        let message = failed_precondition(admit(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            disposition("d-3", "mitigated", Some("d-1")),
            "d3",
        ));
        assert!(message.contains("already superseded by d-2"), "{message}");
        admit(&runtime, ACTION_FINDING, finding("f-2", "sig-2"), "f2").unwrap();
        let mut other = exposure("e-2", VERDICT_UNKNOWN, None);
        other["finding_id"] = "f-2".into();
        admit(&runtime, ACTION_EXPOSURE, other, "e2").unwrap();
        let mut elsewhere = disposition("d-4", "fixed", Some("d-2"));
        elsewhere["exposure_id"] = "e-2".into();
        let message = failed_precondition(admit(
            &runtime,
            ACTION_DISPOSITION_SUPERSEDE,
            elsewhere,
            "d4",
        ));
        assert!(
            message.contains("decides a different exposure"),
            "{message}"
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
