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
//! - A disposition returns to `needs-review` (#1925) when a fact of its
//!   validity basis changes or it expires. The exposure records the current
//!   facts of its deployed target, and a reopen is a governed Action that
//!   supersedes the chain head with a `needs-review` disposition naming the
//!   fact. The exposure is open again while that disposition heads its
//!   chain. The reopen's id derives from the disposition it reopens, so a
//!   repeated pass reopens it once.
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
pub const CERTIFICATION_ID: &str = "cert:security.finding-exposure/v1.2";
/// Certifications this one succeeds, newest first.
const PREVIOUS_CERTIFICATION_IDS: &[&str] = &[
    "cert:security.finding-exposure/v1.1",
    "cert:security.finding-exposure/v1",
];
pub const KIND_FINDING: &str = "security_finding";
pub const KIND_OCCURRENCE: &str = "security_finding_occurrence";
pub const KIND_HYPOTHESIS: &str = "security_hypothesis";
pub const KIND_EXPOSURE: &str = "security_exposure";
pub const KIND_DISPOSITION: &str = "security_disposition";
pub const ACTION_DISPOSITION_RECORD: &str = "security.disposition.record";
pub const ACTION_DISPOSITION_SUPERSEDE: &str = "security.disposition.supersede";
pub const ACTION_DISPOSITION_REOPEN: &str = "security.disposition.reopen";
pub const ACTION_EXPOSURE_BASIS: &str = "security.exposure.basis";
pub const DISPOSITION_ACCEPT_RISK: &str = "accept-risk";
pub const DISPOSITION_NEEDS_REVIEW: &str = "needs-review";
/// Validity basis facts an exposure records the current value of.
pub const BASIS_FACTS: [&str; 5] = [
    "dependency_closure_digest",
    "release_digest",
    "configuration_digest",
    "reachable_markings",
    "advisory_revision",
];
/// An exposure's reachable markings when no marked data is reachable.
pub const NO_MARKINGS: &str = "none";
/// The reopened fact of a disposition that expired.
pub const FACT_EXPIRES_AT: &str = "expires_at_ms";
/// Properties a reopen copies from the disposition it reopens.
const CARRIED_BASIS: [&str; 7] = [
    "dependency_closure_digest",
    "release_digest",
    "configuration_digest",
    "reachable_markings",
    "advisory_revision",
    "asset_criticality",
    "expires_at_ms",
];
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
pub fn validate_object_write(
    db: &RuntimeDb,
    object: &mut Object,
    now_ms: i64,
) -> Result<(), String> {
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
            // A blank fact leaves no trace in the change feed, so it could
            // not reopen anything; an empty markings list is `none`.
            if let Some(fact) = BASIS_FACTS.into_iter().find(|fact| {
                object
                    .properties
                    .get(*fact)
                    .is_some_and(|value| value.trim().is_empty())
            }) {
                return Err(format!(
                    "{fact} must name a value; record no reachable markings as {NO_MARKINGS}"
                ));
            }
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
            match required(object, "disposition")? {
                DISPOSITION_ACCEPT_RISK => {
                    require_marking_for_accepted_risk(db, object, &exposure)?;
                }
                DISPOSITION_NEEDS_REVIEW => validate_reopen(db, object, &exposure, now_ms)?,
                _ => {}
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

/// A `needs-review` disposition reopens the one it supersedes, which must not
/// already be a reopen. It carries that disposition's basis unchanged and
/// names the fact that reopened it: a basis fact whose current value on the
/// exposure differs, or the expiry once it passed. Its marking is at least
/// the reopened disposition's.
fn validate_reopen(
    db: &RuntimeDb,
    object: &mut Object,
    exposure: &Object,
    now_ms: i64,
) -> Result<(), String> {
    let previous_id = required(object, "supersedes")
        .map_err(|_| "a reopen supersedes the disposition it reopens".to_string())?
        .to_string();
    let previous_id = previous_id.as_str();
    let previous = db
        .get_object(previous_id)?
        .filter(|previous| {
            previous.namespace == object.namespace && previous.kind == KIND_DISPOSITION
        })
        .ok_or_else(|| format!("disposition {previous_id} not found in this namespace"))?;
    if previous.properties.get("disposition").map(String::as_str) == Some(DISPOSITION_NEEDS_REVIEW)
    {
        return Err(format!("disposition {previous_id} already needs review"));
    }
    for fact in CARRIED_BASIS {
        if object.properties.get(fact) != previous.properties.get(fact) {
            return Err(format!(
                "a reopen carries the basis of disposition {previous_id} unchanged; {fact} differs"
            ));
        }
    }
    let fact = required(object, "reopened_fact")?.to_string();
    let value = if fact == FACT_EXPIRES_AT {
        let expires = previous
            .properties
            .get(FACT_EXPIRES_AT)
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| format!("disposition {previous_id} has no expiry"))?;
        if expires > now_ms {
            return Err(format!("disposition {previous_id} has not expired"));
        }
        expires.to_string()
    } else if BASIS_FACTS.contains(&fact.as_str()) {
        let current = exposure
            .properties
            .get(&fact)
            .ok_or_else(|| format!("the exposure records no current {fact}"))?;
        if !basis_differs(&previous, &fact, current) {
            return Err(format!(
                "{fact} still matches disposition {previous_id}; it is not reopened"
            ));
        }
        current.clone()
    } else {
        return Err(format!("{fact} is not a validity basis fact"));
    };
    if object
        .properties
        .get("reopened_value")
        .is_some_and(|named| *named != value)
    {
        return Err(format!("reopened_value does not match the current {fact}"));
    }
    object.properties.insert("reopened_value".into(), value);
    // The reopen copies the exposure's current value and the reopened
    // disposition's basis, so it is marked at least as high as both.
    let lattice = namespace_lattice(db, &object.namespace)?;
    let held = crate::sekai::markings::object_marking_token(object).unwrap_or_default();
    for needed in [&previous, exposure]
        .into_iter()
        .filter_map(crate::sekai::markings::object_marking_token)
    {
        if held.is_empty() || !lattice.dominates(held, needed)? {
            return Err(format!(
                "a reopen of disposition {previous_id} needs a marking at least {needed}"
            ));
        }
    }
    Ok(())
}

fn namespace_lattice(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<crate::sekai::classification_lattice::ClassificationLattice, String> {
    Ok(db
        .get_classification_lattice(namespace)?
        .unwrap_or_else(|| {
            crate::sekai::classification_lattice::ClassificationLattice::default_evidence_lattice(
                namespace,
            )
        }))
}

/// Whether the exposure's current value of `fact` differs from the
/// disposition's basis. Reachable markings compare as sets, and absent, empty
/// and `none` all mean no reachable markings, so clearing them is a change.
fn basis_differs(disposition: &Object, fact: &str, current: &str) -> bool {
    let recorded = disposition.properties.get(fact).map_or("", String::as_str);
    if fact != "reachable_markings" {
        return recorded != current;
    }
    let markings = |value: &str| -> std::collections::BTreeSet<String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|marking| !marking.is_empty() && *marking != NO_MARKINGS)
            .map(str::to_string)
            .collect()
    };
    markings(recorded) != markings(current)
}

/// The marking a reopen of `previous` is written under: the join of the
/// reopened disposition's and the exposure's, which it copies values from.
fn reopen_marking(db: &RuntimeDb, previous: &Object) -> Result<Option<String>, String> {
    let exposure = previous
        .properties
        .get("exposure_id")
        .map(|id| db.get_object(id))
        .transpose()?
        .flatten();
    let lattice = namespace_lattice(db, &previous.namespace)?;
    let mut joined: Option<String> = None;
    for marking in [Some(previous), exposure.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(crate::sekai::markings::object_marking_token)
    {
        joined = Some(match joined {
            None => marking.to_string(),
            Some(held) => lattice.join(&held, marking)?.ok_or_else(|| {
                format!(
                    "disposition {} and its exposure have markings {held} and {marking} with no common bound",
                    previous.id
                )
            })?,
        });
    }
    Ok(joined)
}

/// The disposition that heads an exposure's chain: its first disposition,
/// or the latest successor. `None` while the exposure has none.
pub fn disposition_chain_head(
    db: &RuntimeDb,
    namespace: &str,
    exposure_id: &str,
) -> Result<Option<Object>, String> {
    let in_chain = |identity: String| -> Result<Option<Object>, String> {
        Ok(db
            .find_all_by_external_id(&identity)?
            .into_iter()
            .find(|object| object.namespace == namespace && object.kind == KIND_DISPOSITION))
    };
    let Some(mut head) = in_chain(format!("disposition:{exposure_id}"))? else {
        return Ok(None);
    };
    let mut visited = std::collections::BTreeSet::new();
    while let Some(next) = in_chain(format!("disposition-successor:{}", head.id))? {
        if !visited.insert(next.id.clone()) {
            return Err(format!("disposition chain through {} loops", next.id));
        }
        head = next;
    }
    Ok(Some(head))
}

/// What one pass over basis changes did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReopenPass {
    /// The feed position to resume the next pass after.
    pub next_seq: u64,
    /// Ids of the `needs-review` dispositions this pass wrote.
    pub reopened: Vec<String>,
}

/// Reopens the dispositions whose basis no longer matches their exposure
/// (#1925). Reads the committed object-change feed of `namespace` after
/// `after_seq` (the feed object-change subscriptions are built on) for
/// changes to exposure basis facts and for new dispositions. Each changed exposure whose chain head
/// differs in a basis fact is reopened as `actor`. A repeated pass, or one
/// restarted from an earlier position, reopens nothing twice.
pub fn reopen_changed_basis(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    after_seq: u64,
    now_ms: i64,
) -> Result<ReopenPass, String> {
    const PAGE: i32 = 500;
    let mut read_to = after_seq;
    // Each changed exposure, with the feed position of its first change.
    let mut changed = std::collections::BTreeMap::new();
    loop {
        let page = db.list_committed_object_mutations_after(namespace, read_to, PAGE)?;
        for mutation in &page {
            read_to = read_to.max(mutation.seq);
            let field = mutation.change.field.as_str();
            let field = field.strip_prefix("properties.").unwrap_or(field);
            let exposure_id =
                if mutation.object_kind == KIND_EXPOSURE && BASIS_FACTS.contains(&field) {
                    Some(mutation.change.object_id.clone())
                } else if mutation.object_kind == KIND_DISPOSITION && field == "_created" {
                    // A new chain head is checked against the current facts too:
                    // a decision recorded on an outdated basis reopens.
                    db.get_object(&mutation.change.object_id)?
                        .and_then(|disposition| disposition.properties.get("exposure_id").cloned())
                } else {
                    None
                };
            if let Some(exposure_id) = exposure_id {
                changed.entry(exposure_id).or_insert(mutation.seq);
            }
        }
        if page.len() < PAGE as usize {
            break;
        }
    }
    let mut reopened = Vec::new();
    // A change whose reopen is still unresolved (awaiting approval) is read
    // again by the next pass, so the cursor stops before it.
    let mut next_seq = read_to;
    for (exposure_id, first_seq) in changed {
        let Some(exposure) = db
            .get_object(&exposure_id)?
            .filter(|exposure| exposure.namespace == namespace && exposure.kind == KIND_EXPOSURE)
        else {
            continue;
        };
        let Some(head) = disposition_chain_head(db, namespace, &exposure_id)? else {
            continue;
        };
        if is_reopen(&head) {
            continue;
        }
        let differing = BASIS_FACTS.into_iter().find(|fact| {
            exposure
                .properties
                .get(*fact)
                .is_some_and(|current| basis_differs(&head, fact, current))
        });
        let Some(fact) = differing else {
            continue;
        };
        match reopen(db, actor, &head, fact, now_ms)? {
            Reopened::Written(id) => reopened.push(id),
            // The chain moved on (a concurrent successor, which may still
            // carry the old basis) or awaits an approver: the next pass
            // reads this change again and looks at the head it then finds.
            Reopened::Superseded | Reopened::AwaitingApproval => {
                next_seq = next_seq.min(first_seq.saturating_sub(1));
            }
        }
    }
    Ok(ReopenPass { next_seq, reopened })
}

/// Reopens the dispositions heading their chain whose expiry passed by
/// `now_ms` (#1925). A repeated pass reopens nothing twice.
pub fn reopen_expired(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<Vec<String>, String> {
    const PAGE: i32 = 500;
    let mut expired = Vec::new();
    let mut offset = 0;
    loop {
        let page = db.list_objects(&crate::domain::ListFilter {
            kind: Some(KIND_DISPOSITION.into()),
            namespace: Some(namespace.into()),
            limit: PAGE,
            offset,
            ..Default::default()
        })?;
        offset += page.len() as i32;
        expired.extend(
            page.iter()
                .filter(|disposition| {
                    !is_reopen(disposition)
                        && disposition
                            .properties
                            .get(FACT_EXPIRES_AT)
                            .and_then(|value| value.parse::<i64>().ok())
                            .is_some_and(|expires| expires <= now_ms)
                })
                .cloned(),
        );
        if page.len() < PAGE as usize {
            break;
        }
    }
    let mut reopened = Vec::new();
    for disposition in expired {
        // Only the head of a chain is in force; a superseded one is history.
        if !successor_of(db, &disposition)?.is_empty() {
            continue;
        }
        if let Reopened::Written(id) = reopen(db, actor, &disposition, FACT_EXPIRES_AT, now_ms)? {
            reopened.push(id);
        }
    }
    Ok(reopened)
}

fn is_reopen(disposition: &Object) -> bool {
    disposition
        .properties
        .get("disposition")
        .map(String::as_str)
        == Some(DISPOSITION_NEEDS_REVIEW)
}

fn successor_of(db: &RuntimeDb, disposition: &Object) -> Result<Vec<Object>, String> {
    Ok(db
        .find_all_by_external_id(&format!("disposition-successor:{}", disposition.id))?
        .into_iter()
        .filter(|object| {
            object.namespace == disposition.namespace && object.kind == KIND_DISPOSITION
        })
        .collect())
}

/// What one reopen attempt did.
enum Reopened {
    /// This reopen superseded the disposition.
    Written(String),
    /// Another writer moved the chain on first.
    Superseded,
    /// Policy parked it for an approver; a later pass looks again.
    AwaitingApproval,
}

/// Admits the reopen of `previous` for `fact` as `actor`. Its object id
/// derives from `previous`, so it supersedes the disposition at most once,
/// and its idempotency key names the fact in the receipt.
fn reopen(
    db: &RuntimeDb,
    actor: &str,
    previous: &Object,
    fact: &str,
    now_ms: i64,
) -> Result<Reopened, String> {
    let object_id = format!(
        "disposition-reopen-{}",
        &format!("{:x}", Sha256::digest(previous.id.as_bytes()))[..24]
    );
    let mut parameters = serde_json::json!({
        "object_id": object_id,
        "exposure_id": previous.properties.get("exposure_id").cloned().unwrap_or_default(),
        "disposition": DISPOSITION_NEEDS_REVIEW,
        "supersedes": previous.id,
        "reopened_fact": fact,
    });
    for carried in CARRIED_BASIS {
        if let Some(value) = previous.properties.get(carried) {
            parameters[carried] = if carried == FACT_EXPIRES_AT {
                value
                    .parse::<i64>()
                    .map(serde_json::Value::from)
                    .map_err(|_| format!("disposition {} has an invalid expiry", previous.id))?
            } else {
                value.clone().into()
            };
        }
    }
    if let Some(marking) = reopen_marking(db, previous)? {
        parameters["access_marking"] = marking.into();
    }
    // The key names the fact for the receipt and pins the request: a reopen
    // whose parameters changed (a raised marking) is a new request, not a
    // conflicting replay.
    let key = format!(
        "security.reopen:{}:{fact}:{}",
        previous.id,
        &format!("{:x}", Sha256::digest(parameters.to_string().as_bytes()))[..16]
    );
    let admit = |idempotency_key: String| {
        let request = crate::sekai::action_instance_admission::ActionInstanceAdmissionRequest {
            namespace: previous.namespace.clone(),
            type_id: ACTION_DISPOSITION_REOPEN.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters.to_string(),
            idempotency_key,
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: String::new(),
            autonomous_envelope_id: String::new(),
            policy_context: Default::default(),
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: String::new(),
            offline: None,
        };
        crate::sekai::action_instance_admission::ActionInstanceAdmission::new(db, None)
            .admit(request, actor, now_ms)
    };
    use crate::sekai::action_instance::{STATUS_ADMITTED, STATUS_DENIED, STATUS_PARKED};
    // A denial is final for its key. A pass that replays a denied attempt
    // moves on to the next attempt key, so a changed policy takes effect.
    // Attempt keys are numbered, so a pending attempt is found again by its
    // replay instead of being submitted twice; the reopen's object id still
    // allows one successor. Each pass adds at most one denied attempt, so a
    // pass walks only the denials earlier passes recorded.
    let mut attempt: u64 = 0;
    let mut outcome = admit(key.clone());
    while let Ok(denied) = &outcome
        && denied.replay
        && denied.instance.status == STATUS_DENIED
    {
        attempt += 1;
        outcome = admit(format!("{key}:attempt-{attempt}"));
    }
    match outcome {
        Ok(admitted) if admitted.instance.status == STATUS_ADMITTED => {
            // Admission answers for the instance; the chain says whether
            // this reopen is what superseded the disposition.
            if successor_of(db, previous)?
                .iter()
                .any(|successor| successor.id == object_id)
            {
                Ok(Reopened::Written(object_id))
            } else {
                Ok(Reopened::Superseded)
            }
        }
        // Awaits its approver; a grant writes the same reopen.
        Ok(parked) if parked.instance.status == STATUS_PARKED => Ok(Reopened::AwaitingApproval),
        Ok(denied) => Err(format!(
            "reopen of disposition {} was {}: {}",
            previous.id, denied.instance.status, denied.instance.deny_reason
        )),
        // A concurrent pass reopened it for another fact, or someone
        // superseded it: the chain moved on without this reopen.
        Err(_) if !successor_of(db, previous)?.is_empty() => Ok(Reopened::Superseded),
        Err(error) => Err(format!("reopen of disposition {}: {error:?}", previous.id)),
    }
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
                .filter(|marking| !marking.is_empty() && *marking != NO_MARKINGS)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if let Some(marking) = crate::sekai::markings::object_marking_token(exposure) {
        needed.push(marking.to_string());
    }
    // The exposure's current reachable markings bind too, whatever the
    // caller declares.
    if let Some(markings) = exposure.properties.get("reachable_markings") {
        needed.extend(
            markings
                .split(',')
                .map(str::trim)
                .filter(|marking| !marking.is_empty() && *marking != NO_MARKINGS)
                .map(str::to_string),
        );
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
                    .filter(|marking| !marking.is_empty() && *marking != NO_MARKINGS)
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
        let message = validate_object_write(&runtime, &mut changed, 2_000).unwrap_err();
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

    fn basis(closure: &str) -> Value {
        json!({ "object_id": "e-1", "dependency_closure_digest": closure })
    }

    fn head(runtime: &RuntimeDb) -> Object {
        disposition_chain_head(runtime, NAMESPACE, "e-1")
            .unwrap()
            .expect("a disposition")
    }

    /// A false positive bound to closure A returns to needs-review once the
    /// exposure's closure is B, and the receipt names the changed fact; a
    /// repeated or restarted pass reopens nothing twice (#1925).
    #[test]
    fn a_changed_closure_returns_a_false_positive_to_needs_review() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-1", "false-positive", None),
            "d-1",
        )
        .unwrap();
        // The same closure changes nothing.
        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            basis("sha256:closure"),
            "b-a",
        )
        .unwrap();
        let unchanged = reopen_changed_basis(&runtime, NAMESPACE, ACTOR, 0, 3_000).unwrap();
        assert!(unchanged.reopened.is_empty());
        assert_eq!(head(&runtime).id, "d-1");

        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            basis("sha256:closure-b"),
            "b-b",
        )
        .unwrap();
        let pass =
            reopen_changed_basis(&runtime, NAMESPACE, ACTOR, unchanged.next_seq, 3_000).unwrap();
        assert_eq!(pass.reopened.len(), 1);
        let reopened = head(&runtime);
        assert_eq!(reopened.id, pass.reopened[0]);
        assert_eq!(reopened.properties["disposition"], DISPOSITION_NEEDS_REVIEW);
        assert_eq!(reopened.properties["supersedes"], "d-1");
        assert_eq!(
            reopened.properties["reopened_fact"],
            "dependency_closure_digest"
        );
        assert_eq!(reopened.properties["reopened_value"], "sha256:closure-b");
        assert_eq!(
            reopened.properties["dependency_closure_digest"],
            "sha256:closure"
        );
        let instance = runtime
            .list_action_instances(NAMESPACE, None, None, 50)
            .unwrap()
            .into_iter()
            .find(|instance| instance.type_id == ACTION_DISPOSITION_REOPEN)
            .expect("reopen instance");
        let key = instance.idempotency_key.clone();
        assert!(
            key.starts_with("security.reopen:d-1:dependency_closure_digest:"),
            "{key}"
        );
        let receipt = runtime
            .get_operation_receipt(&instance.operation_id)
            .unwrap()
            .expect("receipt");
        assert_eq!(receipt.events[0].attributes["idempotency_key"], key);
        assert_eq!(receipt.events[0].attributes["object_id"], reopened.id);

        // Passes from the start again reopen nothing twice.
        for _ in 0..2 {
            assert!(
                reopen_changed_basis(&runtime, NAMESPACE, ACTOR, 0, 4_000)
                    .unwrap()
                    .reopened
                    .is_empty()
            );
        }
        assert_eq!(head(&runtime).id, reopened.id);
    }

    /// A disposition returns to needs-review at its expiry, once, also
    /// after a restart (#1925).
    #[test]
    fn an_expired_disposition_reopens_once_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let open = || {
            RuntimeDb::Sqlite(Arc::new(
                SekaiDb::new(path.to_str().expect("utf-8 path")).expect("file sqlite"),
            ))
        };
        let runtime = open();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        admit(&runtime, ACTION_FINDING, finding("f-1", "sig-1"), "f").unwrap();
        admit(
            &runtime,
            ACTION_EXPOSURE,
            exposure("e-1", VERDICT_UNKNOWN, None),
            "e",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-1", "mitigated", None),
            "d-1",
        )
        .unwrap();
        assert!(
            reopen_expired(&runtime, NAMESPACE, ACTOR, 8_999)
                .unwrap()
                .is_empty()
        );
        let reopened = reopen_expired(&runtime, NAMESPACE, ACTOR, 9_000).unwrap();
        assert_eq!(reopened.len(), 1);
        drop(runtime);

        let restarted = open();
        assert!(
            reopen_expired(&restarted, NAMESPACE, ACTOR, 10_000)
                .unwrap()
                .is_empty()
        );
        let head = head(&restarted);
        assert_eq!(head.id, reopened[0]);
        assert_eq!(head.properties["reopened_fact"], FACT_EXPIRES_AT);
        assert_eq!(head.properties["reopened_value"], "9000");
        let dispositions = restarted
            .list_objects(&crate::domain::ListFilter {
                kind: Some(KIND_DISPOSITION.into()),
                namespace: Some(NAMESPACE.into()),
                limit: 50,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(dispositions.len(), 2);
    }

    /// A reopen is refused unless its fact really changed or the expiry
    /// passed, and it carries the reopened basis unchanged (#1925).
    #[test]
    fn a_reopen_must_be_warranted() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-1", "false-positive", None),
            "d-1",
        )
        .unwrap();
        let mut reopen = disposition("d-2", DISPOSITION_NEEDS_REVIEW, Some("d-1"));
        reopen["reopened_fact"] = "dependency_closure_digest".into();
        let message = failed_precondition(admit(
            &runtime,
            ACTION_DISPOSITION_REOPEN,
            reopen.clone(),
            "r-1",
        ));
        assert!(
            message.contains("no current dependency_closure_digest"),
            "{message}"
        );
        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            basis("sha256:closure"),
            "b",
        )
        .unwrap();
        let message = failed_precondition(admit(
            &runtime,
            ACTION_DISPOSITION_REOPEN,
            reopen.clone(),
            "r-2",
        ));
        assert!(message.contains("still matches"), "{message}");

        let mut early = reopen.clone();
        early["reopened_fact"] = FACT_EXPIRES_AT.into();
        let message = failed_precondition(admit(&runtime, ACTION_DISPOSITION_REOPEN, early, "r-3"));
        assert!(message.contains("has not expired"), "{message}");

        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            basis("sha256:closure-b"),
            "b-2",
        )
        .unwrap();
        let mut altered = reopen.clone();
        altered["release_digest"] = "sha256:other".into();
        let message =
            failed_precondition(admit(&runtime, ACTION_DISPOSITION_REOPEN, altered, "r-4"));
        assert!(message.contains("unchanged"), "{message}");
        admit(&runtime, ACTION_DISPOSITION_REOPEN, reopen, "r-5").unwrap();
        assert_eq!(head(&runtime).id, "d-2");
    }

    /// Clearing a basis fact is a change: reachable markings recorded as
    /// `none` reopen a disposition that relied on some. A blank value is
    /// refused (#1925).
    #[test]
    fn a_cleared_basis_fact_reopens_its_disposition() {
        let runtime = with_exposure();
        let mut decided = disposition("d-1", "false-positive", None);
        decided["reachable_markings"] = "internal".into();
        admit(&runtime, ACTION_DISPOSITION_RECORD, decided, "d-1").unwrap();
        assert!(
            admit(
                &runtime,
                ACTION_EXPOSURE_BASIS,
                json!({ "object_id": "e-1", "reachable_markings": "" }),
                "blank",
            )
            .is_err()
        );
        // The same list in another order changes nothing.
        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            json!({ "object_id": "e-1", "reachable_markings": " internal" }),
            "same",
        )
        .unwrap();
        assert!(
            reopen_changed_basis(&runtime, NAMESPACE, ACTOR, 0, 3_000)
                .unwrap()
                .reopened
                .is_empty()
        );
        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            json!({ "object_id": "e-1", "reachable_markings": NO_MARKINGS }),
            "b",
        )
        .unwrap();
        let pass = reopen_changed_basis(&runtime, NAMESPACE, ACTOR, 0, 3_000).unwrap();
        assert_eq!(pass.reopened.len(), 1);
        let reopened = head(&runtime);
        assert_eq!(reopened.properties["reopened_fact"], "reachable_markings");
        assert_eq!(reopened.properties["reopened_value"], NO_MARKINGS);
    }

    /// A reopen copies the exposure's current value, so it is marked at
    /// least as high as the exposure, not only the reopened disposition
    /// (#1925).
    #[test]
    fn a_reopen_is_marked_at_least_as_high_as_its_exposure() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-1", "false-positive", None),
            "d-1",
        )
        .unwrap();
        let mut exposure = runtime.get_object("e-1").unwrap().unwrap();
        exposure
            .properties
            .insert("access_marking".into(), "confidential".into());
        exposure.properties.insert(
            "dependency_closure_digest".into(),
            "sha256:closure-b".into(),
        );
        runtime.update_object(&exposure).unwrap();

        let mut reopen = disposition("d-2", DISPOSITION_NEEDS_REVIEW, Some("d-1"));
        reopen["reopened_fact"] = "dependency_closure_digest".into();
        reopen["access_marking"] = "internal".into();
        let message = failed_precondition(admit_cleared(
            &runtime,
            ACTION_DISPOSITION_REOPEN,
            reopen,
            "r-low",
            "internal",
        ));
        assert!(message.contains("at least confidential"), "{message}");

        assert_eq!(
            reopen_expired(&runtime, NAMESPACE, ACTOR, 9_000)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            head(&runtime)
                .properties
                .get("access_marking")
                .map(String::as_str),
            Some("confidential")
        );
    }

    /// Accepting risk needs clearance for the exposure's current reachable
    /// markings even when the disposition declares none (#1925).
    #[test]
    fn accepting_risk_honours_the_exposures_current_reachable_markings() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            json!({ "object_id": "e-1", "reachable_markings": "confidential" }),
            "b",
        )
        .unwrap();
        let mut accept = disposition("d-1", DISPOSITION_ACCEPT_RISK, None);
        accept["access_marking"] = "internal".into();
        let message = failed_precondition(admit_cleared(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            accept,
            "d-1",
            "internal",
        ));
        assert!(message.contains("confidential"), "{message}");
    }

    /// A reopen that admission parks or denies reports nothing reopened,
    /// and a pass still holding the change retries it (#1925).
    #[test]
    fn a_reopen_admission_did_not_write_is_not_reported() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-1", "false-positive", None),
            "d-1",
        )
        .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all(NAMESPACE);
        policy.default_decision = crate::sekai::action_policy::ActionDecision::Deny;
        runtime.upsert_action_policy(&policy).unwrap();
        assert!(reopen_expired(&runtime, NAMESPACE, ACTOR, 9_000).is_err());
        assert_eq!(head(&runtime).id, "d-1");

        // Once policy allows it, the next pass reopens it.
        runtime
            .upsert_action_policy(&crate::sekai::action_policy::ActionPolicy::allow_all(
                NAMESPACE,
            ))
            .unwrap();
        assert_eq!(
            reopen_expired(&runtime, NAMESPACE, ACTOR, 9_500)
                .unwrap()
                .len(),
            1
        );
        assert_ne!(head(&runtime).id, "d-1");
    }

    /// A reopen parked for an approver keeps its change for the next pass,
    /// so a decision against it does not lose the change (#1925).
    #[test]
    fn a_parked_reopen_keeps_its_change_for_the_next_pass() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-1", "false-positive", None),
            "d-1",
        )
        .unwrap();
        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            basis("sha256:closure-b"),
            "b",
        )
        .unwrap();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all(NAMESPACE);
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        runtime.upsert_action_policy(&policy).unwrap();
        let parked = reopen_changed_basis(&runtime, NAMESPACE, ACTOR, 0, 3_000).unwrap();
        assert!(parked.reopened.is_empty());
        // The cursor stops before the basis change, so the next pass reads
        // it again.
        let change_seq = runtime
            .list_committed_object_mutations_after(NAMESPACE, 0, 100)
            .unwrap()
            .into_iter()
            .find(|mutation| mutation.change.field.ends_with("dependency_closure_digest"))
            .unwrap()
            .seq;
        assert!(parked.next_seq < change_seq);
        assert_eq!(head(&runtime).id, "d-1");
        // Until its approver decides, every pass holds the change.
        let again =
            reopen_changed_basis(&runtime, NAMESPACE, ACTOR, parked.next_seq, 4_000).unwrap();
        assert!(again.reopened.is_empty());
        assert_eq!(again.next_seq, parked.next_seq);
    }

    /// A disposition recorded on a basis the exposure no longer has is
    /// reopened, even when the exposure's change was read before (#1925).
    #[test]
    fn a_decision_on_an_outdated_basis_reopens() {
        let runtime = with_exposure();
        admit(
            &runtime,
            ACTION_EXPOSURE_BASIS,
            basis("sha256:closure-b"),
            "b",
        )
        .unwrap();
        let first = reopen_changed_basis(&runtime, NAMESPACE, ACTOR, 0, 3_000).unwrap();
        assert!(first.reopened.is_empty());
        admit(
            &runtime,
            ACTION_DISPOSITION_RECORD,
            disposition("d-1", "false-positive", None),
            "d-1",
        )
        .unwrap();
        let pass = reopen_changed_basis(&runtime, NAMESPACE, ACTOR, first.next_seq, 4_000).unwrap();
        assert_eq!(pass.reopened.len(), 1);
        assert_eq!(
            head(&runtime).properties["reopened_fact"],
            "dependency_closure_digest"
        );
    }
}
