//! Conformance evidence for issue #501.
//!
//! This is a parser-neutral edge contract. It projects the #499 profile into
//! a small, deterministic RDF/OWL/PROV-O-shaped triple set and exercises the
//! import guardrails. It deliberately does not parse Turtle, fetch an
//! ontology, run a reasoner, or write an inferred fact.

use sekai_chisei::chisei::epistemic_descriptor::MAX_OBSERVED_AT_MS;
use sekai_chisei::sekai::ontology::{OntologyClass, OntologyProperty, OntologyRegistry};
use sekai_chisei::sekai::schema::PropertyType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const PROFILE_PACKAGE: &str = include_str!("../examples/epistemic-replication/profile-v1.json");
const SOURCE_FORMAT: &str = "rdf/owl/prov-o-canonical-triples";
const PROFILE_NAME: &str = "example.epistemic-replication";
const PROFILE_VERSION: &str = "1.0.0";
const MAPPING_VERSION: &str = "sekai.epistemic-interoperability/v1";
const NAMESPACE: &str = "replication";
const BASE: &str = "https://sekai.local/epistemic/example.epistemic-replication/v1#";
const MAX_TRIPLES: usize = 512;
const MAX_SERIALIZED_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_PROPERTY: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property";
const RDFS_DOMAIN: &str = "http://www.w3.org/2000/01/rdf-schema#domain";
const RDFS_RANGE: &str = "http://www.w3.org/2000/01/rdf-schema#range";
const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const OWL_CLASS: &str = "http://www.w3.org/2002/07/owl#Class";
const OWL_EQUIVALENT: &str = "http://www.w3.org/2002/07/owl#equivalentClass";
const OWL_DISJOINT: &str = "http://www.w3.org/2002/07/owl#disjointWith";
const OWL_INVERSE: &str = "http://www.w3.org/2002/07/owl#inverseOf";
const OWL_TRANSITIVE: &str = "http://www.w3.org/2002/07/owl#TransitiveProperty";
const OWL_IMPORTS: &str = "http://www.w3.org/2002/07/owl#imports";
const OWL_RESTRICTION: &str = "http://www.w3.org/2002/07/owl#Restriction";
const OWL_SAME_AS: &str = "http://www.w3.org/2002/07/owl#sameAs";
const PROV_ENTITY: &str = "http://www.w3.org/ns/prov#Entity";
const PROV_ACTIVITY: &str = "http://www.w3.org/ns/prov#Activity";
const PROV_AGENT: &str = "http://www.w3.org/ns/prov#Agent";
const PROV_USED: &str = "http://www.w3.org/ns/prov#used";
const PROV_DERIVED_FROM: &str = "http://www.w3.org/ns/prov#wasDerivedFrom";
const PROV_GENERATED_BY: &str = "http://www.w3.org/ns/prov#wasGeneratedBy";
const PROV_ASSOCIATED_WITH: &str = "http://www.w3.org/ns/prov#wasAssociatedWith";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const SEKAI_ASSERTION_MODE: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#assertionMode";
const SEKAI_LIFECYCLE_STATUS: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#lifecycleStatus";
const SEKAI_EVIDENCE_STATUS: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#evidenceStatus";
const SEKAI_EVIDENCE_STANCE: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#evidenceStance";
const SEKAI_SOURCE_DIGEST: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#sourceDigest";
const SEKAI_REQUIRED: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#required";
const SEKAI_PROPERTY_DESCRIPTION: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#propertyDescription";
const SEKAI_OBSERVED_AT: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#observedAtUnixMs";
const SEKAI_CONFIDENCE_BASIS: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#confidenceBasis";
const SEKAI_PRODUCER_CONFIDENCE_BPS: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#producerConfidenceBps";
const RELATION_PREFIX: &str =
    "https://sekai.local/epistemic/example.epistemic-replication/v1#relation/";
const ALLOWED_RELATIONS: &[&str] = &["evidence_for", "derived_from"];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct DomainSchemaPackage {
    contract_version: String,
    schema_id: String,
    version: String,
    classes: Vec<DomainClass>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct DomainClass {
    name: String,
    description: String,
    properties: Vec<DomainProperty>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct DomainProperty {
    name: String,
    property_type: String,
    required: bool,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", content = "value")]
enum Term {
    Iri(String),
    Literal(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Triple {
    subject: String,
    predicate: String,
    object: Term,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct LossRecord {
    code: String,
    term: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct FactMetadata {
    identity: String,
    assertion_mode: String,
    lifecycle_status: String,
    evidence_status: String,
    evidence_stance: String,
    observed_at_unix_ms: i64,
    source_digest: String,
    producer_confidence_bps: u16,
    confidence_basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct IdentityBinding {
    source_format: String,
    source_identity: String,
    source_iri: String,
    mapping_version: String,
    local_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportedProperty {
    domain: String,
    range: String,
    required: bool,
    description: String,
}

#[derive(Debug, Default)]
struct PropertyDraft {
    domain: Option<String>,
    range: Option<String>,
    required: Option<bool>,
    description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportedRelation {
    domain: String,
    range: String,
}

#[derive(Debug, Default)]
struct RelationDraft {
    domain: Option<String>,
    range: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct InteropEnvelope {
    source_format: String,
    profile: String,
    profile_version: String,
    mapping_version: String,
    namespace: String,
    ontology_revision: String,
    profile_digest: String,
    receipt_digest: String,
    confidence_basis: String,
    identity_bindings: Vec<IdentityBinding>,
    facts: Vec<FactMetadata>,
    references: BTreeMap<String, String>,
    triples: Vec<Triple>,
    losses: Vec<LossRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportReport {
    source_format: String,
    profile: String,
    profile_version: String,
    mapping_version: String,
    namespace: String,
    confidence_basis: String,
    profile_digest: String,
    receipt_digest: String,
    ontology_revision: String,
    classes: BTreeSet<String>,
    class_types: BTreeMap<String, String>,
    relations: BTreeMap<String, ImportedRelation>,
    evidence_edges: BTreeSet<(String, String, String)>,
    provenance_edges: BTreeSet<(String, String, String)>,
    provenance_types: BTreeMap<String, BTreeSet<String>>,
    assertion_modes: BTreeMap<String, String>,
    lifecycle_statuses: BTreeMap<String, String>,
    evidence_statuses: BTreeMap<String, String>,
    evidence_stances: BTreeMap<String, String>,
    source_digests: BTreeMap<String, String>,
    producer_confidence_bps: BTreeMap<String, u16>,
    observed_at_unix_ms: BTreeMap<String, i64>,
    confidence_bases: BTreeMap<String, String>,
    properties: BTreeMap<String, ImportedProperty>,
    losses: Vec<LossRecord>,
    external_iris: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
struct ExportCandidate {
    name: &'static str,
    namespace: &'static str,
    authorized: bool,
    disclosed: bool,
}

fn digest(value: impl AsRef<[u8]>) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_ref()))
}

fn package() -> DomainSchemaPackage {
    let mut package: DomainSchemaPackage =
        serde_json::from_str(PROFILE_PACKAGE).expect("#499 profile package is valid JSON");
    package
        .classes
        .sort_by(|left, right| left.name.cmp(&right.name));
    for class in &mut package.classes {
        class
            .properties
            .sort_by(|left, right| left.name.cmp(&right.name));
    }
    package
}

fn profile_registry(package: &DomainSchemaPackage) -> OntologyRegistry {
    let classes = package
        .classes
        .iter()
        .map(|class| OntologyClass {
            name: class.name.clone(),
            description: class.description.clone(),
            superclasses: Vec::new(),
            equivalent_classes: Vec::new(),
            disjoint_classes: Vec::new(),
            properties: class
                .properties
                .iter()
                .map(|property| OntologyProperty {
                    name: property.name.clone(),
                    prop_type: PropertyType::parse(&property.property_type)
                        .expect("#499 property types are part of the Sekai vocabulary"),
                    required: property.required,
                    description: property.description.clone(),
                })
                .collect(),
            is_builtin: false,
            mapped_kind: String::new(),
        })
        .collect();
    OntologyRegistry::from_parts(classes, Vec::new())
}

fn reconstructed_registry(
    package: &DomainSchemaPackage,
    imported: &ImportReport,
) -> OntologyRegistry {
    let classes = package
        .classes
        .iter()
        .map(|class| OntologyClass {
            name: class.name.clone(),
            description: class.description.clone(),
            superclasses: Vec::new(),
            equivalent_classes: Vec::new(),
            disjoint_classes: Vec::new(),
            properties: class
                .properties
                .iter()
                .map(|property| {
                    let identity = property_iri(&class.name, &property.name);
                    let projected = imported
                        .properties
                        .get(&identity)
                        .expect("every profile property must round-trip");
                    assert_eq!(projected.domain, class_iri(&class.name));
                    assert_eq!(projected.range, XSD_STRING);
                    OntologyProperty {
                        name: property.name.clone(),
                        prop_type: PropertyType::parse(&property.property_type)
                            .expect("#499 property types are known"),
                        required: projected.required,
                        description: projected.description.clone(),
                    }
                })
                .collect(),
            is_builtin: false,
            mapped_kind: String::new(),
        })
        .collect();
    OntologyRegistry::from_parts(classes, Vec::new())
}

fn class_iri(name: &str) -> String {
    format!("{BASE}class/{name}")
}

fn property_iri(class: &str, property: &str) -> String {
    format!("{BASE}property/{class}/{property}")
}

fn relation_iri(name: &str) -> String {
    format!("{BASE}relation/{name}")
}

fn instance_iri(name: &str) -> String {
    format!("{BASE}instance/{name}")
}

fn iri(value: impl AsRef<str>) -> Term {
    Term::Iri(value.as_ref().to_string())
}

fn literal(value: impl Into<String>) -> Term {
    Term::Literal(value.into())
}

fn require_literal<'a>(term: &'a Term, field: &str) -> Result<&'a str, String> {
    match term {
        Term::Literal(value) => Ok(value),
        Term::Iri(_) => Err(format!("{field} must be a literal")),
    }
}

fn metadata_subject_is_governed(
    subject_supported: bool,
    subject_is_governed: bool,
    subject: &str,
    predicate: &str,
    losses: &mut Vec<LossRecord>,
) -> bool {
    if subject_supported && !subject_is_governed {
        losses.push(LossRecord {
            code: "metadata_subject_not_entity".into(),
            term: subject.to_string(),
            detail: format!("{predicate} applies only to governed entities"),
        });
    }
    subject_is_governed
}

fn triple(subject: impl AsRef<str>, predicate: &str, object: Term) -> Triple {
    Triple {
        subject: subject.as_ref().to_string(),
        predicate: predicate.to_string(),
        object,
    }
}

fn all_candidates() -> Vec<ExportCandidate> {
    vec![
        ExportCandidate {
            name: "claim",
            namespace: "replication",
            authorized: true,
            disclosed: true,
        },
        ExportCandidate {
            name: "supporting",
            namespace: "replication",
            authorized: true,
            disclosed: true,
        },
        ExportCandidate {
            name: "contradicting",
            namespace: "replication",
            authorized: false,
            disclosed: false,
        },
        ExportCandidate {
            name: "assessment",
            namespace: "replication",
            authorized: true,
            disclosed: true,
        },
        ExportCandidate {
            name: "activity",
            namespace: "replication",
            authorized: true,
            disclosed: true,
        },
        ExportCandidate {
            name: "agent",
            namespace: "replication",
            authorized: true,
            disclosed: true,
        },
        ExportCandidate {
            name: "foreign-claim",
            namespace: "other-tenant",
            authorized: true,
            disclosed: true,
        },
    ]
}

fn authorized_names(candidates: &[ExportCandidate], namespace: &str) -> BTreeSet<String> {
    candidates
        .iter()
        .filter(|candidate| {
            candidate.namespace == namespace && candidate.authorized && candidate.disclosed
        })
        .map(|candidate| candidate.name.to_string())
        .collect()
}

fn build_export(visible: &BTreeSet<String>) -> InteropEnvelope {
    let package = package();
    let registry = profile_registry(&package);
    let profile_digest = digest(PROFILE_PACKAGE);
    let claim_digest = digest("claim:replication-001");
    let supporting_digest = digest("evidence:supporting:v1");
    let contradicting_digest = digest("evidence:contradicting:v1");
    let assessment_digest = digest("assessment:replication-001:v1");
    let receipt_digest = digest("receipt:replication-001:v1");
    let claim = instance_iri("claim-replication-001");
    let supporting = instance_iri("evidence-supporting");
    let contradicting = instance_iri("evidence-contradicting");
    let assessment = instance_iri("assessment-replication-001");
    let activity = instance_iri("activity-replication-evaluation");
    let agent = instance_iri("producer-replication-lab");
    let mut triples = Vec::new();

    for class in &package.classes {
        triples.push(triple(class_iri(&class.name), RDF_TYPE, iri(OWL_CLASS)));
        for property in &class.properties {
            let property_id = property_iri(&class.name, &property.name);
            triples.push(triple(&property_id, RDF_TYPE, iri(RDF_PROPERTY)));
            triples.push(triple(
                &property_id,
                RDFS_DOMAIN,
                iri(class_iri(&class.name)),
            ));
            triples.push(triple(&property_id, RDFS_RANGE, iri(XSD_STRING)));
            triples.push(triple(
                &property_id,
                SEKAI_REQUIRED,
                literal(property.required.to_string()),
            ));
            triples.push(triple(
                &property_id,
                SEKAI_PROPERTY_DESCRIPTION,
                literal(property.description.clone()),
            ));
        }
    }

    // The profile package has no relation declarations. These two links are
    // the existing generic evidence/lineage vocabulary projected at the edge;
    // supporting versus contradicting polarity stays in evidenceStance.
    for relation in ["evidence_for", "derived_from"] {
        let relation_id = relation_iri(relation);
        triples.push(triple(&relation_id, RDF_TYPE, iri(RDF_PROPERTY)));
        triples.push(triple(&relation_id, RDFS_DOMAIN, iri(PROV_ENTITY)));
        triples.push(triple(
            &relation_id,
            RDFS_RANGE,
            iri(if relation == "derived_from" {
                PROV_ENTITY.to_string()
            } else {
                class_iri("Claim")
            }),
        ));
    }

    let claim_visible = visible.contains("claim");
    let supporting_visible = visible.contains("supporting");
    let contradicting_visible = visible.contains("contradicting");
    let assessment_visible = visible.contains("assessment");
    let activity_visible = visible.contains("activity");
    let agent_visible = visible.contains("agent");

    if claim_visible {
        triples.push(triple(&claim, RDF_TYPE, iri(PROV_ENTITY)));
        triples.push(triple(&claim, RDF_TYPE, iri(class_iri("Claim"))));
        triples.push(triple(&claim, SEKAI_ASSERTION_MODE, literal("asserted")));
        triples.push(triple(&claim, SEKAI_LIFECYCLE_STATUS, literal("retracted")));
        triples.push(triple(&claim, SEKAI_EVIDENCE_STATUS, literal("contested")));
        triples.push(triple(&claim, SEKAI_EVIDENCE_STANCE, literal("unknown")));
        triples.push(triple(
            &claim,
            SEKAI_SOURCE_DIGEST,
            literal(claim_digest.clone()),
        ));
        triples.push(triple(&claim, SEKAI_OBSERVED_AT, literal("1700000000000")));
        triples.push(triple(
            &claim,
            SEKAI_CONFIDENCE_BASIS,
            literal("producer_input"),
        ));
        triples.push(triple(
            &claim,
            SEKAI_PRODUCER_CONFIDENCE_BPS,
            literal("8000"),
        ));
    }
    if supporting_visible {
        triples.push(triple(&supporting, RDF_TYPE, iri(PROV_ENTITY)));
        triples.push(triple(
            &supporting,
            SEKAI_ASSERTION_MODE,
            literal("asserted"),
        ));
        triples.push(triple(
            &supporting,
            SEKAI_LIFECYCLE_STATUS,
            literal("current"),
        ));
        triples.push(triple(
            &supporting,
            SEKAI_EVIDENCE_STATUS,
            literal("supported"),
        ));
        triples.push(triple(
            &supporting,
            SEKAI_EVIDENCE_STANCE,
            literal("supporting"),
        ));
        triples.push(triple(
            &supporting,
            SEKAI_SOURCE_DIGEST,
            literal(supporting_digest.clone()),
        ));
        triples.push(triple(
            &supporting,
            SEKAI_CONFIDENCE_BASIS,
            literal("producer_input"),
        ));
        triples.push(triple(
            &supporting,
            SEKAI_PRODUCER_CONFIDENCE_BPS,
            literal("9000"),
        ));
        triples.push(triple(
            &supporting,
            SEKAI_OBSERVED_AT,
            literal("1700000000100"),
        ));
        if claim_visible {
            triples.push(triple(
                &supporting,
                relation_iri("evidence_for").as_str(),
                iri(claim.clone()),
            ));
        }
    }
    if contradicting_visible {
        triples.push(triple(&contradicting, RDF_TYPE, iri(PROV_ENTITY)));
        triples.push(triple(
            &contradicting,
            SEKAI_ASSERTION_MODE,
            literal("asserted"),
        ));
        triples.push(triple(
            &contradicting,
            SEKAI_LIFECYCLE_STATUS,
            literal("retracted"),
        ));
        triples.push(triple(
            &contradicting,
            SEKAI_EVIDENCE_STATUS,
            literal("contested"),
        ));
        triples.push(triple(
            &contradicting,
            SEKAI_EVIDENCE_STANCE,
            literal("contradicting"),
        ));
        triples.push(triple(
            &contradicting,
            SEKAI_SOURCE_DIGEST,
            literal(contradicting_digest.clone()),
        ));
        triples.push(triple(
            &contradicting,
            SEKAI_CONFIDENCE_BASIS,
            literal("producer_input"),
        ));
        triples.push(triple(
            &contradicting,
            SEKAI_PRODUCER_CONFIDENCE_BPS,
            literal("2000"),
        ));
        triples.push(triple(
            &contradicting,
            SEKAI_OBSERVED_AT,
            literal("1700000000200"),
        ));
        if claim_visible {
            triples.push(triple(
                &contradicting,
                relation_iri("evidence_for").as_str(),
                iri(claim.clone()),
            ));
        }
    }
    if assessment_visible {
        triples.push(triple(&assessment, RDF_TYPE, iri(PROV_ENTITY)));
        triples.push(triple(
            &assessment,
            SEKAI_ASSERTION_MODE,
            literal("derived"),
        ));
        triples.push(triple(
            &assessment,
            SEKAI_LIFECYCLE_STATUS,
            literal("current"),
        ));
        triples.push(triple(
            &assessment,
            SEKAI_EVIDENCE_STATUS,
            literal("contested"),
        ));
        triples.push(triple(
            &assessment,
            SEKAI_EVIDENCE_STANCE,
            literal("unknown"),
        ));
        triples.push(triple(
            &assessment,
            SEKAI_SOURCE_DIGEST,
            literal(assessment_digest.clone()),
        ));
        triples.push(triple(
            &assessment,
            SEKAI_CONFIDENCE_BASIS,
            literal("producer_input"),
        ));
        triples.push(triple(
            &assessment,
            SEKAI_PRODUCER_CONFIDENCE_BPS,
            literal("7000"),
        ));
        triples.push(triple(
            &assessment,
            SEKAI_OBSERVED_AT,
            literal("1700000000300"),
        ));
        if claim_visible {
            triples.push(triple(&assessment, PROV_DERIVED_FROM, iri(claim.clone())));
            triples.push(triple(
                &assessment,
                relation_iri("derived_from").as_str(),
                iri(claim.clone()),
            ));
        }
        if activity_visible {
            triples.push(triple(
                &assessment,
                PROV_GENERATED_BY,
                iri(activity.clone()),
            ));
        }
    }
    if activity_visible {
        triples.push(triple(&activity, RDF_TYPE, iri(PROV_ACTIVITY)));
        if claim_visible {
            triples.push(triple(&activity, PROV_USED, iri(claim.clone())));
        }
        if agent_visible {
            triples.push(triple(&agent, RDF_TYPE, iri(PROV_AGENT)));
            triples.push(triple(&activity, PROV_ASSOCIATED_WITH, iri(&agent)));
        }
    }

    triples.sort();
    triples.dedup();

    let mut facts = Vec::new();
    if claim_visible {
        facts.push(FactMetadata {
            identity: claim.clone(),
            assertion_mode: "asserted".into(),
            lifecycle_status: "retracted".into(),
            evidence_status: "contested".into(),
            evidence_stance: "unknown".into(),
            observed_at_unix_ms: 1_700_000_000_000,
            source_digest: claim_digest.clone(),
            producer_confidence_bps: 8000,
            confidence_basis: "producer_input".into(),
        });
    }
    if supporting_visible {
        facts.push(FactMetadata {
            identity: supporting.clone(),
            assertion_mode: "asserted".into(),
            lifecycle_status: "current".into(),
            evidence_status: "supported".into(),
            evidence_stance: "supporting".into(),
            observed_at_unix_ms: 1_700_000_000_100,
            source_digest: supporting_digest.clone(),
            producer_confidence_bps: 9000,
            confidence_basis: "producer_input".into(),
        });
    }
    if contradicting_visible {
        facts.push(FactMetadata {
            identity: contradicting.clone(),
            assertion_mode: "asserted".into(),
            lifecycle_status: "retracted".into(),
            evidence_status: "contested".into(),
            evidence_stance: "contradicting".into(),
            observed_at_unix_ms: 1_700_000_000_200,
            source_digest: contradicting_digest.clone(),
            producer_confidence_bps: 2000,
            confidence_basis: "producer_input".into(),
        });
    }
    if assessment_visible {
        facts.push(FactMetadata {
            identity: assessment.clone(),
            assertion_mode: "derived".into(),
            lifecycle_status: "current".into(),
            evidence_status: "contested".into(),
            evidence_stance: "unknown".into(),
            observed_at_unix_ms: 1_700_000_000_300,
            source_digest: assessment_digest.clone(),
            producer_confidence_bps: 7000,
            confidence_basis: "producer_input".into(),
        });
    }
    facts.sort();

    let mut references = BTreeMap::from([
        ("profile".into(), profile_digest.clone()),
        ("receipt".into(), receipt_digest.clone()),
    ]);
    if claim_visible {
        references.insert("claim".into(), claim_digest);
    }
    if supporting_visible {
        references.insert("supporting".into(), supporting_digest);
    }
    if contradicting_visible {
        references.insert("contradicting".into(), contradicting_digest);
    }
    if assessment_visible {
        references.insert("assessment".into(), assessment_digest);
    }

    let mut binding_ids = facts
        .iter()
        .map(|fact| fact.identity.clone())
        .collect::<BTreeSet<_>>();
    if activity_visible {
        binding_ids.insert(activity);
    }
    if agent_visible {
        binding_ids.insert(agent);
    }
    let identity_bindings = binding_ids
        .into_iter()
        .map(|identity| IdentityBinding {
            source_format: SOURCE_FORMAT.into(),
            source_identity: PROFILE_NAME.into(),
            source_iri: identity.clone(),
            mapping_version: MAPPING_VERSION.into(),
            local_id: identity,
        })
        .collect();

    InteropEnvelope {
        source_format: SOURCE_FORMAT.into(),
        profile: package.schema_id,
        profile_version: package.version,
        mapping_version: MAPPING_VERSION.into(),
        namespace: NAMESPACE.into(),
        ontology_revision: registry.revision(),
        profile_digest,
        receipt_digest,
        confidence_basis: "bounded edge projection; no external inference".into(),
        identity_bindings,
        facts,
        references,
        triples,
        losses: Vec::new(),
    }
}

fn is_standard_term(iri: &str) -> bool {
    matches!(
        iri,
        RDF_TYPE
            | RDF_PROPERTY
            | RDFS_DOMAIN
            | RDFS_RANGE
            | RDFS_SUBCLASS
            | OWL_CLASS
            | OWL_EQUIVALENT
            | OWL_DISJOINT
            | OWL_INVERSE
            | OWL_TRANSITIVE
            | OWL_IMPORTS
            | OWL_RESTRICTION
            | OWL_SAME_AS
            | PROV_ENTITY
            | PROV_ACTIVITY
            | PROV_AGENT
            | PROV_USED
            | PROV_DERIVED_FROM
            | PROV_GENERATED_BY
            | PROV_ASSOCIATED_WITH
            | XSD_STRING
    )
}

fn is_local_vocabulary(iri: &str) -> bool {
    iri.starts_with(&format!("{BASE}class/"))
        || iri.starts_with(&format!("{BASE}property/"))
        || iri.starts_with(RELATION_PREFIX)
}

fn fixture_authorized_bindings() -> BTreeMap<String, String> {
    [
        "claim-replication-001",
        "evidence-supporting",
        "evidence-contradicting",
        "assessment-replication-001",
        "activity-replication-evaluation",
        "producer-replication-lab",
    ]
    .into_iter()
    .map(|name| {
        let identity = instance_iri(name);
        (identity.clone(), identity)
    })
    .collect()
}

fn validate_identity_bindings(
    envelope: &InteropEnvelope,
    authorized_bindings: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut bindings = BTreeMap::new();
    let mut local_ids = BTreeSet::new();
    for binding in &envelope.identity_bindings {
        if binding.source_format != envelope.source_format
            || binding.mapping_version != envelope.mapping_version
            || binding.source_identity != envelope.profile
        {
            return Err("identity binding is outside the envelope contract".into());
        }
        for (label, value) in [
            ("source_iri", binding.source_iri.as_str()),
            ("local_id", binding.local_id.as_str()),
        ] {
            if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || !is_absolute_iri_ref(value)
            {
                return Err(format!(
                    "identity binding {label} is not a valid absolute IRI"
                ));
            }
        }
        if !binding.local_id.starts_with(BASE) || is_local_vocabulary(&binding.local_id) {
            return Err("identity binding local_id must name a governed object".into());
        }
        if binding.source_iri != binding.local_id {
            return Err(
                "identity binding must be a local self-binding; external resolution requires authenticated context"
                    .into(),
            );
        }
        if authorized_bindings.get(&binding.source_iri) != Some(&binding.local_id) {
            return Err("identity binding is not authorized by the import context".into());
        }
        if bindings
            .insert(binding.source_iri.clone(), binding.local_id.clone())
            .is_some()
        {
            return Err("duplicate identity binding source IRI".into());
        }
        if !local_ids.insert(binding.local_id.clone()) {
            return Err("duplicate identity binding local ID".into());
        }
    }
    Ok(bindings)
}

fn bound_identity(identity: &str, bindings: &BTreeMap<String, String>) -> Option<String> {
    bindings.get(identity).cloned().or_else(|| {
        bindings
            .values()
            .find(|local_id| local_id.as_str() == identity)
            .cloned()
    })
}

fn is_governed_identity(identity: &str, bindings: &BTreeMap<String, String>) -> bool {
    identity.starts_with(BASE)
        && !is_local_vocabulary(identity)
        && bindings
            .get(identity)
            .is_some_and(|local_id| local_id == identity)
}

fn is_supported_term(identity: &str, bindings: &BTreeMap<String, String>) -> bool {
    is_standard_term(identity)
        || is_local_vocabulary(identity)
        || is_governed_identity(identity, bindings)
}

fn is_blank(iri: &str) -> bool {
    iri.starts_with("_:")
}

fn is_absolute_iri_ref(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    if scheme.is_empty()
        || !scheme.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic()
            } else {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            }
        })
    {
        return false;
    }
    !value.chars().any(|character| {
        character.is_control()
            || character.is_whitespace()
            || matches!(
                character,
                '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\'
            )
    })
}

fn sort_losses(losses: &mut Vec<LossRecord>) {
    losses.sort();
    losses.dedup();
}

fn bind_source_digest(
    digests: &mut BTreeMap<String, String>,
    identity: String,
    digest: String,
) -> Result<(), String> {
    if !is_sha256_digest(&digest) {
        return Err(format!(
            "source digest for {identity} is not sha256:<64-lowercase-hex>"
        ));
    }
    if let Some(existing) = digests.get(&identity) {
        if existing != &digest {
            return Err(format!("conflicting source digest for {identity}"));
        }
    } else {
        digests.insert(identity, digest);
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bind_string_field(
    values: &mut BTreeMap<String, String>,
    identity: String,
    value: String,
    field: &str,
) -> Result<(), String> {
    if let Some(existing) = values.get(&identity) {
        if existing != &value {
            return Err(format!("conflicting {field} for {identity}"));
        }
    } else {
        values.insert(identity, value);
    }
    Ok(())
}

fn bind_i64_field(
    values: &mut BTreeMap<String, i64>,
    identity: String,
    value: i64,
    field: &str,
) -> Result<(), String> {
    if let Some(existing) = values.get(&identity) {
        if existing != &value {
            return Err(format!("conflicting {field} for {identity}"));
        }
    } else {
        values.insert(identity, value);
    }
    Ok(())
}

fn bind_u16_field(
    values: &mut BTreeMap<String, u16>,
    identity: String,
    value: u16,
    field: &str,
) -> Result<(), String> {
    if let Some(existing) = values.get(&identity) {
        if existing != &value {
            return Err(format!("conflicting {field} for {identity}"));
        }
    } else {
        values.insert(identity, value);
    }
    Ok(())
}

fn bind_optional<T: PartialEq>(slot: &mut Option<T>, value: T, field: &str) -> Result<(), String> {
    if let Some(existing) = slot {
        if existing != &value {
            return Err(format!("conflicting {field}"));
        }
    } else {
        *slot = Some(value);
    }
    Ok(())
}

fn validate_fact_labels(fact: &FactMetadata) -> Result<(), String> {
    if fact.identity.is_empty()
        || fact.identity.len() > MAX_IDENTIFIER_BYTES
        || fact.identity.chars().any(char::is_control)
    {
        return Err("fact identity is not bounded".into());
    }
    if !["asserted", "derived"].contains(&fact.assertion_mode.as_str()) {
        return Err("unsupported assertion mode".into());
    }
    if !["current", "stale", "retracted", "superseded"].contains(&fact.lifecycle_status.as_str()) {
        return Err("unsupported lifecycle status".into());
    }
    if !["supported", "contested", "insufficient", "unknown"]
        .contains(&fact.evidence_status.as_str())
    {
        return Err("unsupported evidence status".into());
    }
    if !["supporting", "contradicting", "unknown"].contains(&fact.evidence_stance.as_str()) {
        return Err("unsupported evidence stance".into());
    }
    if fact.confidence_basis.is_empty()
        || fact.confidence_basis.len() > MAX_IDENTIFIER_BYTES * 4
        || fact.confidence_basis.chars().any(char::is_control)
    {
        return Err("confidence basis is not bounded".into());
    }
    if fact.confidence_basis != "producer_input" || fact.producer_confidence_bps > 10_000 {
        return Err("producer confidence requires producer_input basis and a bounded score".into());
    }
    if !is_sha256_digest(&fact.source_digest) {
        return Err("source digest must be sha256:<64-lowercase-hex>".into());
    }
    if !(0..=MAX_OBSERVED_AT_MS).contains(&fact.observed_at_unix_ms) {
        return Err("observed time is outside the bounded range".into());
    }
    Ok(())
}

fn reference_identity(label: &str) -> Option<String> {
    match label {
        "claim" => Some(instance_iri("claim-replication-001")),
        "supporting" => Some(instance_iri("evidence-supporting")),
        "contradicting" => Some(instance_iri("evidence-contradicting")),
        "assessment" => Some(instance_iri("assessment-replication-001")),
        _ => None,
    }
}

fn require_bound_identity(
    identity: &str,
    bindings: &BTreeMap<String, String>,
) -> Result<(), String> {
    if identity.starts_with(BASE) && !is_local_vocabulary(identity) {
        match bindings.get(identity) {
            Some(local_id) if local_id == identity => Ok(()),
            Some(_) => Err(format!("identity binding remaps local IRI {identity}")),
            None if bindings.values().any(|local_id| local_id == identity) => Ok(()),
            None => Err(format!("identity binding required for {identity}")),
        }
    } else {
        Ok(())
    }
}

fn validate_envelope_shape(envelope: &InteropEnvelope) -> Result<(), String> {
    for (label, value) in [
        ("source_format", envelope.source_format.as_str()),
        ("profile", envelope.profile.as_str()),
        ("profile_version", envelope.profile_version.as_str()),
        ("mapping_version", envelope.mapping_version.as_str()),
        ("namespace", envelope.namespace.as_str()),
        ("ontology_revision", envelope.ontology_revision.as_str()),
        ("profile_digest", envelope.profile_digest.as_str()),
        ("receipt_digest", envelope.receipt_digest.as_str()),
    ] {
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(format!("{label} is not a bounded identifier"));
        }
    }
    if envelope.confidence_basis.is_empty()
        || envelope.confidence_basis.len() > MAX_IDENTIFIER_BYTES * 4
        || envelope.confidence_basis.chars().any(char::is_control)
    {
        return Err("confidence basis is not bounded".into());
    }
    if envelope.triples.len() > MAX_TRIPLES {
        return Err(format!(
            "triple count {} exceeds bound {MAX_TRIPLES}",
            envelope.triples.len()
        ));
    }
    if envelope
        .triples
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err("triples must be strictly sorted and unique".into());
    }
    if envelope
        .facts
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err("facts must be strictly sorted and unique".into());
    }
    if envelope
        .losses
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err("loss records must be strictly sorted and unique".into());
    }
    if envelope
        .identity_bindings
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err("identity bindings must be strictly sorted and unique".into());
    }
    let bytes = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_SERIALIZED_BYTES {
        return Err(format!(
            "serialized envelope {} exceeds bound {MAX_SERIALIZED_BYTES}",
            bytes.len()
        ));
    }
    Ok(())
}

fn import_document(
    envelope: &InteropEnvelope,
    authorized_bindings: &BTreeMap<String, String>,
) -> Result<ImportReport, String> {
    validate_envelope_shape(envelope)?;
    let package = package();
    if envelope.source_format != SOURCE_FORMAT
        || envelope.profile != PROFILE_NAME
        || envelope.profile_version != PROFILE_VERSION
        || envelope.mapping_version != MAPPING_VERSION
    {
        return Err("unsupported interop profile or mapping version".into());
    }
    if envelope.namespace != NAMESPACE {
        return Err("namespace is outside the pinned profile".into());
    }
    if envelope.profile_digest != digest(PROFILE_PACKAGE) {
        return Err("profile digest does not match the pinned package".into());
    }
    if !is_sha256_digest(&envelope.receipt_digest) {
        return Err("receipt digest must be sha256:<64-lowercase-hex>".into());
    }
    if envelope.ontology_revision != profile_registry(&package).revision() {
        return Err("ontology revision does not match the pinned package".into());
    }
    let identity_bindings = validate_identity_bindings(envelope, authorized_bindings)?;
    let mut losses = envelope.losses.clone();
    let mut classes = BTreeSet::new();
    let mut class_types = BTreeMap::new();
    let mut relation_drafts = BTreeMap::<String, RelationDraft>::new();
    let mut declared_relations = BTreeSet::new();
    let mut evidence_edges = BTreeSet::new();
    let mut provenance_edges = BTreeSet::new();
    let mut provenance_types = BTreeMap::<String, BTreeSet<String>>::new();
    let mut assertion_modes = BTreeMap::new();
    let mut lifecycle_statuses = BTreeMap::new();
    let mut evidence_statuses = BTreeMap::new();
    let mut evidence_stances = BTreeMap::new();
    let mut source_digests = BTreeMap::new();
    let mut producer_confidence_bps = BTreeMap::new();
    let mut observed_at_unix_ms = BTreeMap::new();
    let mut confidence_bases = BTreeMap::new();
    let mut property_drafts = BTreeMap::<String, PropertyDraft>::new();
    let mut declared_properties = BTreeSet::new();
    let mut external_iris = BTreeSet::new();
    let mut fact_identities = BTreeSet::new();
    let mut metadata_subjects = BTreeSet::new();
    let expected_classes = package
        .classes
        .iter()
        .map(|class| class.name.clone())
        .collect::<BTreeSet<_>>();
    let expected_property_definitions = package
        .classes
        .iter()
        .flat_map(|class| {
            class.properties.iter().map(|property| {
                (
                    property_iri(&class.name, &property.name),
                    (
                        class_iri(&class.name),
                        XSD_STRING.to_string(),
                        property.required,
                        property.description.clone(),
                    ),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let expected_properties = expected_property_definitions
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_relations = ALLOWED_RELATIONS
        .iter()
        .map(|name| relation_iri(name))
        .collect::<BTreeSet<_>>();

    if envelope.references.get("profile") != Some(&envelope.profile_digest)
        || envelope.references.get("receipt") != Some(&envelope.receipt_digest)
    {
        return Err("profile and receipt references must match envelope digests".into());
    }
    for (label, digest) in &envelope.references {
        if let Some(identity) = reference_identity(label) {
            if identity_bindings.get(&identity) == Some(&identity) {
                bind_source_digest(&mut source_digests, identity, digest.clone())?;
            } else {
                losses.push(LossRecord {
                    code: "unbound_reference".into(),
                    term: label.clone(),
                    detail: "known references require an authorized local self-binding".into(),
                });
            }
        } else if label != "profile" && label != "receipt" {
            losses.push(LossRecord {
                code: "unsupported_reference".into(),
                term: label.clone(),
                detail: "reference label is outside the bounded profile".into(),
            });
        }
    }

    for fact in &envelope.facts {
        validate_fact_labels(fact)?;
        if is_blank(&fact.identity) {
            return Err("blank-node identity is not supported".into());
        }
        require_bound_identity(&fact.identity, &identity_bindings)?;
        let identity = bound_identity(&fact.identity, &identity_bindings)
            .unwrap_or_else(|| fact.identity.clone());
        if !is_governed_identity(&identity, &identity_bindings) {
            external_iris.insert(fact.identity.clone());
            losses.push(LossRecord {
                code: "external_iri_not_reconciled".into(),
                term: fact.identity.clone(),
                detail: "identity requires an explicit local binding".into(),
            });
            continue;
        }
        fact_identities.insert(identity.clone());
        bind_string_field(
            &mut assertion_modes,
            identity.clone(),
            fact.assertion_mode.clone(),
            "assertion mode",
        )?;
        bind_string_field(
            &mut lifecycle_statuses,
            identity.clone(),
            fact.lifecycle_status.clone(),
            "lifecycle status",
        )?;
        bind_string_field(
            &mut evidence_statuses,
            identity.clone(),
            fact.evidence_status.clone(),
            "evidence status",
        )?;
        bind_string_field(
            &mut evidence_stances,
            identity.clone(),
            fact.evidence_stance.clone(),
            "evidence stance",
        )?;
        bind_source_digest(
            &mut source_digests,
            identity.clone(),
            fact.source_digest.clone(),
        )?;
        bind_u16_field(
            &mut producer_confidence_bps,
            identity.clone(),
            fact.producer_confidence_bps,
            "producer confidence",
        )?;
        bind_i64_field(
            &mut observed_at_unix_ms,
            identity.clone(),
            fact.observed_at_unix_ms,
            "observation time",
        )?;
        bind_string_field(
            &mut confidence_bases,
            identity,
            fact.confidence_basis.clone(),
            "confidence basis",
        )?;
    }

    for triple in &envelope.triples {
        if is_blank(&triple.subject) {
            return Err("blank-node subject is not supported".into());
        }
        if triple.subject.len() > MAX_IDENTIFIER_BYTES || !is_absolute_iri_ref(&triple.subject) {
            return Err("subject is not a valid absolute IRI".into());
        }
        if triple.predicate.len() > MAX_IDENTIFIER_BYTES || !is_absolute_iri_ref(&triple.predicate)
        {
            return Err("predicate is not a valid absolute IRI".into());
        }
        require_bound_identity(&triple.subject, &identity_bindings)?;
        let object_iri = match &triple.object {
            Term::Iri(value) => Some(value.as_str()),
            Term::Literal(value) => {
                if value.len() > MAX_IDENTIFIER_BYTES * 4 || value.chars().any(char::is_control) {
                    return Err("literal exceeds bounded size".into());
                }
                None
            }
        };
        let subject_id = bound_identity(&triple.subject, &identity_bindings)
            .unwrap_or_else(|| triple.subject.clone());
        let subject_is_governed = is_governed_identity(&subject_id, &identity_bindings);
        let subject_supported = is_local_vocabulary(&subject_id) || subject_is_governed;
        let mut object_id = None;
        if let Some(object) = object_iri {
            if is_blank(object) {
                return Err("blank-node object is not supported".into());
            }
            if object.len() > MAX_IDENTIFIER_BYTES || !is_absolute_iri_ref(object) {
                return Err("object is not a valid absolute IRI".into());
            }
            require_bound_identity(object, &identity_bindings)?;
            object_id = bound_identity(object, &identity_bindings).or_else(|| {
                is_supported_term(object, &identity_bindings).then(|| object.to_string())
            });
            if object_id.is_none() {
                external_iris.insert(object.to_string());
                losses.push(LossRecord {
                    code: "external_iri_not_reconciled".into(),
                    term: object.to_string(),
                    detail: "identity requires an explicit local binding".into(),
                });
            }
        }
        let object_supported = object_iri.is_some() && object_id.is_some();
        let object_is_governed = object_id
            .as_deref()
            .is_some_and(|identity| is_governed_identity(identity, &identity_bindings));
        if !subject_supported {
            external_iris.insert(triple.subject.clone());
            losses.push(LossRecord {
                code: "external_iri_not_reconciled".into(),
                term: triple.subject.clone(),
                detail: "identity requires an explicit local binding".into(),
            });
        }
        if subject_is_governed
            && matches!(
                triple.predicate.as_str(),
                SEKAI_ASSERTION_MODE
                    | SEKAI_LIFECYCLE_STATUS
                    | SEKAI_EVIDENCE_STATUS
                    | SEKAI_EVIDENCE_STANCE
                    | SEKAI_SOURCE_DIGEST
                    | SEKAI_OBSERVED_AT
                    | SEKAI_CONFIDENCE_BASIS
                    | SEKAI_PRODUCER_CONFIDENCE_BPS
            )
        {
            metadata_subjects.insert(subject_id.clone());
        }
        match triple.predicate.as_str() {
            OWL_IMPORTS => losses.push(LossRecord {
                code: "unsupported_owl_imports".into(),
                term: triple.predicate.clone(),
                detail: "remote ontology dereferencing is disabled".into(),
            }),
            OWL_SAME_AS => losses.push(LossRecord {
                code: "identity_reconciliation_unsupported".into(),
                term: triple.predicate.clone(),
                detail: "sameAs cannot bind or merge local objects".into(),
            }),
            OWL_RESTRICTION => losses.push(LossRecord {
                code: "unsupported_owl_restriction".into(),
                term: triple.predicate.clone(),
                detail: "restrictions do not enter the bounded profile".into(),
            }),
            RDFS_SUBCLASS | OWL_EQUIVALENT | OWL_DISJOINT | OWL_INVERSE => {
                losses.push(LossRecord {
                    code: "unsupported_owl_entailment".into(),
                    term: triple.predicate.clone(),
                    detail: "OWL entailment is not imported by the bounded profile".into(),
                })
            }
            RDF_TYPE => match &triple.object {
                Term::Iri(value) if subject_supported && value == OWL_CLASS => {
                    if let Some(name) = subject_id.strip_prefix(&format!("{BASE}class/")) {
                        if !expected_classes.contains(name) {
                            return Err(format!("class {name} is outside the pinned profile"));
                        }
                        classes.insert(name.to_string());
                    } else {
                        losses.push(LossRecord {
                            code: "unsupported_type".into(),
                            term: value.clone(),
                            detail: "owl:Class applies only to pinned class IRIs".into(),
                        });
                    }
                }
                Term::Iri(value) if value == RDF_PROPERTY => {
                    if subject_supported {
                        if subject_id.starts_with(RELATION_PREFIX) {
                            if !expected_relations.contains(&subject_id) {
                                return Err("relation is outside the bounded profile".into());
                            }
                            declared_relations.insert(subject_id.clone());
                            relation_drafts.entry(subject_id.clone()).or_default();
                        } else if subject_id.starts_with(&format!("{BASE}property/")) {
                            if !expected_properties.contains(&subject_id) {
                                return Err("property is outside the pinned profile".into());
                            }
                            declared_properties.insert(subject_id.clone());
                            property_drafts.entry(subject_id.clone()).or_default();
                        } else {
                            losses.push(LossRecord {
                                code: "unsupported_type".into(),
                                term: value.clone(),
                                detail:
                                    "rdf:Property applies only to pinned properties and relations"
                                        .into(),
                            });
                        }
                    }
                }
                Term::Iri(value) if value.starts_with(&format!("{BASE}class/")) => {
                    if subject_is_governed {
                        let Some(name) = value.strip_prefix(&format!("{BASE}class/")) else {
                            unreachable!("class prefix guard matched");
                        };
                        if !expected_classes.contains(name) {
                            return Err(format!("class {name} is outside the pinned profile"));
                        }
                        bind_string_field(
                            &mut class_types,
                            subject_id.clone(),
                            value.clone(),
                            "class type",
                        )?;
                    } else if subject_supported {
                        losses.push(LossRecord {
                            code: "unsupported_type".into(),
                            term: value.clone(),
                            detail: "profile class types apply only to governed entities".into(),
                        });
                    }
                }
                Term::Iri(value) if value == OWL_RESTRICTION => losses.push(LossRecord {
                    code: "unsupported_owl_restriction".into(),
                    term: value.clone(),
                    detail: "restrictions do not enter the bounded profile".into(),
                }),
                Term::Iri(value) if value == OWL_TRANSITIVE => losses.push(LossRecord {
                    code: "unsupported_owl_entailment".into(),
                    term: value.clone(),
                    detail: "OWL entailment is not imported by the bounded profile".into(),
                }),
                Term::Iri(value)
                    if subject_is_governed
                        && [PROV_ENTITY, PROV_ACTIVITY, PROV_AGENT].contains(&value.as_str()) =>
                {
                    provenance_types
                        .entry(subject_id.clone())
                        .or_default()
                        .insert(value.clone());
                }
                Term::Iri(value) => losses.push(LossRecord {
                    code: "unsupported_type".into(),
                    term: value.clone(),
                    detail: "rdf:type is retained only for the bounded vocabulary".into(),
                }),
                Term::Literal(_) => return Err("rdf:type object must be an IRI".into()),
            },
            RDFS_DOMAIN => {
                let Term::Iri(_) = &triple.object else {
                    return Err("domain must be an IRI".into());
                };
                if subject_supported
                    && object_supported
                    && subject_id.starts_with(&format!("{BASE}property/"))
                {
                    let value = object_id
                        .clone()
                        .expect("supported domain has an IRI object");
                    bind_optional(
                        &mut property_drafts
                            .entry(subject_id.clone())
                            .or_default()
                            .domain,
                        value,
                        "property domain",
                    )?;
                } else if subject_supported
                    && object_supported
                    && subject_id.starts_with(RELATION_PREFIX)
                {
                    let value = object_id
                        .clone()
                        .expect("supported domain has an IRI object");
                    bind_optional(
                        &mut relation_drafts
                            .entry(subject_id.clone())
                            .or_default()
                            .domain,
                        value,
                        "relation domain",
                    )?;
                }
            }
            RDFS_RANGE => {
                let Term::Iri(_) = &triple.object else {
                    return Err("range must be an IRI".into());
                };
                if subject_supported
                    && object_supported
                    && subject_id.starts_with(&format!("{BASE}property/"))
                {
                    let value = object_id
                        .clone()
                        .expect("supported range has an IRI object");
                    bind_optional(
                        &mut property_drafts.entry(subject_id.clone()).or_default().range,
                        value,
                        "property range",
                    )?;
                } else if subject_supported
                    && object_supported
                    && subject_id.starts_with(RELATION_PREFIX)
                {
                    let value = object_id
                        .clone()
                        .expect("supported range has an IRI object");
                    bind_optional(
                        &mut relation_drafts.entry(subject_id.clone()).or_default().range,
                        value,
                        "relation range",
                    )?;
                }
            }
            PROV_DERIVED_FROM | PROV_GENERATED_BY | PROV_USED | PROV_ASSOCIATED_WITH => {
                if subject_is_governed && object_is_governed {
                    provenance_edges.insert((
                        subject_id.clone(),
                        triple.predicate.clone(),
                        object_id
                            .clone()
                            .expect("supported provenance edge has an IRI object"),
                    ));
                } else {
                    losses.push(LossRecord {
                        code: "unbound_edge_endpoint".into(),
                        term: triple.predicate.clone(),
                        detail: "edge endpoints remain opaque until explicitly bound".into(),
                    });
                }
            }
            SEKAI_ASSERTION_MODE => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_ASSERTION_MODE,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "assertion mode")?;
                    if !["asserted", "derived"].contains(&value) {
                        return Err("unsupported assertion mode".into());
                    }
                    bind_string_field(
                        &mut assertion_modes,
                        subject_id.clone(),
                        value.to_string(),
                        "assertion mode",
                    )?;
                }
            }
            SEKAI_LIFECYCLE_STATUS => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_LIFECYCLE_STATUS,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "lifecycle status")?;
                    if !["current", "stale", "retracted", "superseded"].contains(&value) {
                        return Err("unsupported lifecycle status".into());
                    }
                    bind_string_field(
                        &mut lifecycle_statuses,
                        subject_id.clone(),
                        value.to_string(),
                        "lifecycle status",
                    )?;
                }
            }
            SEKAI_EVIDENCE_STATUS => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_EVIDENCE_STATUS,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "evidence status")?;
                    if !["supported", "contested", "insufficient", "unknown"].contains(&value) {
                        return Err("unsupported evidence status".into());
                    }
                    bind_string_field(
                        &mut evidence_statuses,
                        subject_id.clone(),
                        value.to_string(),
                        "evidence status",
                    )?;
                }
            }
            SEKAI_EVIDENCE_STANCE => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_EVIDENCE_STANCE,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "evidence stance")?;
                    if !["supporting", "contradicting", "unknown"].contains(&value) {
                        return Err("unsupported evidence stance".into());
                    }
                    bind_string_field(
                        &mut evidence_stances,
                        subject_id.clone(),
                        value.to_string(),
                        "evidence stance",
                    )?;
                }
            }
            SEKAI_SOURCE_DIGEST => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_SOURCE_DIGEST,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "source digest")?;
                    bind_source_digest(&mut source_digests, subject_id.clone(), value.to_string())?;
                }
            }
            SEKAI_PRODUCER_CONFIDENCE_BPS => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_PRODUCER_CONFIDENCE_BPS,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "producer confidence")?;
                    let parsed = value
                        .parse::<u16>()
                        .map_err(|_| "producer confidence must be an integer".to_string())?;
                    if parsed > 10_000 {
                        return Err("producer confidence exceeds 10000 basis points".into());
                    }
                    bind_u16_field(
                        &mut producer_confidence_bps,
                        subject_id.clone(),
                        parsed,
                        "producer confidence",
                    )?;
                }
            }
            SEKAI_REQUIRED => {
                if expected_properties.contains(&subject_id) {
                    let value = require_literal(&triple.object, "required property flag")?;
                    let parsed = value
                        .parse::<bool>()
                        .map_err(|_| "required property flag must be boolean".to_string())?;
                    bind_optional(
                        &mut property_drafts
                            .entry(subject_id.clone())
                            .or_default()
                            .required,
                        parsed,
                        "property required flag",
                    )?;
                } else if subject_supported {
                    losses.push(LossRecord {
                        code: "metadata_subject_not_property".into(),
                        term: subject_id.clone(),
                        detail: "required metadata applies only to pinned properties".into(),
                    });
                }
            }
            SEKAI_PROPERTY_DESCRIPTION => {
                if expected_properties.contains(&subject_id) {
                    let value = require_literal(&triple.object, "property description")?;
                    bind_optional(
                        &mut property_drafts
                            .entry(subject_id.clone())
                            .or_default()
                            .description,
                        value.to_string(),
                        "property description",
                    )?;
                } else if subject_supported {
                    losses.push(LossRecord {
                        code: "metadata_subject_not_property".into(),
                        term: subject_id.clone(),
                        detail: "description metadata applies only to pinned properties".into(),
                    });
                }
            }
            SEKAI_OBSERVED_AT => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_OBSERVED_AT,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "observation time")?;
                    let parsed = value
                        .parse::<i64>()
                        .map_err(|_| "observed time must be an integer".to_string())?;
                    if !(0..=MAX_OBSERVED_AT_MS).contains(&parsed) {
                        return Err("observation time is outside the bounded range".into());
                    }
                    bind_i64_field(
                        &mut observed_at_unix_ms,
                        subject_id.clone(),
                        parsed,
                        "observation time",
                    )?;
                }
            }
            SEKAI_CONFIDENCE_BASIS => {
                if metadata_subject_is_governed(
                    subject_supported,
                    subject_is_governed,
                    &subject_id,
                    SEKAI_CONFIDENCE_BASIS,
                    &mut losses,
                ) {
                    let value = require_literal(&triple.object, "confidence basis")?;
                    if value.is_empty()
                        || value.len() > MAX_IDENTIFIER_BYTES * 4
                        || value.chars().any(char::is_control)
                    {
                        return Err("confidence basis is not bounded".into());
                    }
                    bind_string_field(
                        &mut confidence_bases,
                        subject_id.clone(),
                        value.to_string(),
                        "confidence basis",
                    )?;
                }
            }
            predicate if predicate.starts_with(RELATION_PREFIX) => {
                let name = &predicate[RELATION_PREFIX.len()..];
                if !ALLOWED_RELATIONS.contains(&name) {
                    losses.push(LossRecord {
                        code: "unsupported_relation".into(),
                        term: predicate.to_string(),
                        detail: "relation is retained only in the loss report".into(),
                    });
                } else if subject_is_governed && object_is_governed {
                    evidence_edges.insert((
                        subject_id.clone(),
                        predicate.to_string(),
                        object_id
                            .clone()
                            .expect("supported evidence edge has an IRI object"),
                    ));
                } else {
                    losses.push(LossRecord {
                        code: "unbound_edge_endpoint".into(),
                        term: predicate.to_string(),
                        detail: "edge endpoints remain opaque until explicitly bound".into(),
                    });
                }
            }
            predicate if predicate.starts_with(BASE) => losses.push(LossRecord {
                code: "unsupported_predicate".into(),
                term: predicate.to_string(),
                detail: "predicate is retained only in the loss report".into(),
            }),
            _ => losses.push(LossRecord {
                code: "unsupported_predicate".into(),
                term: triple.predicate.clone(),
                detail: "predicate is retained only in the loss report".into(),
            }),
        }
    }

    for identity in &metadata_subjects {
        if !fact_identities.contains(identity) {
            return Err(format!(
                "epistemic metadata requires a fact record for {identity}"
            ));
        }
    }
    for identity in &fact_identities {
        let complete = assertion_modes.contains_key(identity)
            && lifecycle_statuses.contains_key(identity)
            && evidence_statuses.contains_key(identity)
            && evidence_stances.contains_key(identity)
            && source_digests.contains_key(identity)
            && producer_confidence_bps.contains_key(identity)
            && observed_at_unix_ms.contains_key(identity)
            && confidence_bases.contains_key(identity);
        if !complete {
            return Err(format!(
                "epistemic fact metadata is incomplete for {identity}"
            ));
        }
    }

    let invalid_evidence = evidence_edges
        .iter()
        .filter(|edge| {
            let object_is_valid = if edge.1 == relation_iri("derived_from") {
                provenance_types
                    .get(&edge.2)
                    .is_some_and(|kinds| kinds.contains(PROV_ENTITY))
            } else {
                class_types
                    .get(&edge.2)
                    .is_some_and(|class| class == &class_iri("Claim"))
            };
            provenance_types
                .get(&edge.0)
                .is_none_or(|kinds| !kinds.contains(PROV_ENTITY))
                || !object_is_valid
        })
        .cloned()
        .collect::<Vec<_>>();
    for edge in invalid_evidence {
        evidence_edges.remove(&edge);
        let expected_object = if edge.1 == relation_iri("derived_from") {
            "PROV Entity"
        } else {
            "Claim"
        };
        losses.push(LossRecord {
            code: "relation_endpoint_type_mismatch".into(),
            term: edge.1,
            detail: format!(
                "evidence relations require a PROV Entity subject and {expected_object} object"
            ),
        });
    }

    let invalid_provenance = provenance_edges
        .iter()
        .filter_map(|edge| {
            let (expected_subject, expected_object) = match edge.1.as_str() {
                PROV_DERIVED_FROM => (PROV_ENTITY, PROV_ENTITY),
                PROV_GENERATED_BY => (PROV_ENTITY, PROV_ACTIVITY),
                PROV_USED => (PROV_ACTIVITY, PROV_ENTITY),
                PROV_ASSOCIATED_WITH => (PROV_ACTIVITY, PROV_AGENT),
                _ => return None,
            };
            let valid = provenance_types
                .get(&edge.0)
                .is_some_and(|kinds| kinds.contains(expected_subject))
                && provenance_types
                    .get(&edge.2)
                    .is_some_and(|kinds| kinds.contains(expected_object));
            (!valid).then(|| (edge.clone(), expected_subject, expected_object))
        })
        .collect::<Vec<_>>();
    for (edge, expected_subject, expected_object) in invalid_provenance {
        provenance_edges.remove(&edge);
        losses.push(LossRecord {
            code: "prov_endpoint_type_mismatch".into(),
            term: edge.1,
            detail: format!(
                "PROV edge requires {expected_subject} subject and {expected_object} object"
            ),
        });
    }

    let mut relations = BTreeMap::new();
    for (identity, draft) in relation_drafts {
        relations.insert(
            identity.clone(),
            ImportedRelation {
                domain: draft
                    .domain
                    .ok_or_else(|| format!("relation {identity} is missing a domain"))?,
                range: draft
                    .range
                    .ok_or_else(|| format!("relation {identity} is missing a range"))?,
            },
        );
    }

    let mut properties = BTreeMap::new();
    for (identity, draft) in property_drafts {
        properties.insert(
            identity.clone(),
            ImportedProperty {
                domain: draft
                    .domain
                    .ok_or_else(|| format!("property {identity} is missing a domain"))?,
                range: draft
                    .range
                    .ok_or_else(|| format!("property {identity} is missing a range"))?,
                required: draft
                    .required
                    .ok_or_else(|| format!("property {identity} is missing required metadata"))?,
                description: draft.description.unwrap_or_default(),
            },
        );
    }
    if classes != expected_classes {
        return Err("class declarations do not match the pinned profile".into());
    }
    if properties.keys().cloned().collect::<BTreeSet<_>>() != expected_properties {
        return Err("property declarations do not match the pinned profile".into());
    }
    if declared_properties != expected_properties {
        return Err("property rdf:type declarations do not match the pinned profile".into());
    }
    if relations.keys().cloned().collect::<BTreeSet<_>>() != expected_relations {
        return Err("relation declarations do not match the bounded profile".into());
    }
    if declared_relations != expected_relations {
        return Err("relation rdf:type declarations do not match the bounded profile".into());
    }
    for (identity, property) in &properties {
        let Some((expected_domain, expected_range, expected_required, expected_description)) =
            expected_property_definitions.get(identity)
        else {
            return Err("property declaration does not match the pinned profile".into());
        };
        if property.domain != *expected_domain
            || property.range != *expected_range
            || property.required != *expected_required
            || property.description != *expected_description
        {
            return Err(format!(
                "property metadata does not match the pinned profile for {identity}"
            ));
        }
    }
    for (identity, relation) in &relations {
        let expected_range = if identity == &relation_iri("derived_from") {
            PROV_ENTITY.to_string()
        } else {
            class_iri("Claim")
        };
        if relation.domain != PROV_ENTITY || relation.range != expected_range {
            return Err("relation declaration does not match the bounded profile".into());
        }
    }
    sort_losses(&mut losses);
    Ok(ImportReport {
        source_format: envelope.source_format.clone(),
        profile: envelope.profile.clone(),
        profile_version: envelope.profile_version.clone(),
        mapping_version: envelope.mapping_version.clone(),
        namespace: envelope.namespace.clone(),
        confidence_basis: envelope.confidence_basis.clone(),
        profile_digest: envelope.profile_digest.clone(),
        receipt_digest: envelope.receipt_digest.clone(),
        ontology_revision: envelope.ontology_revision.clone(),
        classes,
        class_types,
        relations,
        evidence_edges,
        provenance_edges,
        provenance_types,
        assertion_modes,
        lifecycle_statuses,
        evidence_statuses,
        evidence_stances,
        source_digests,
        producer_confidence_bps,
        observed_at_unix_ms,
        confidence_bases,
        properties,
        losses,
        external_iris,
    })
}

fn ntriples(envelope: &InteropEnvelope) -> String {
    envelope
        .triples
        .iter()
        .map(|triple| {
            let object = match &triple.object {
                Term::Iri(value) => format!("<{value}>"),
                Term::Literal(value) => {
                    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
                }
            };
            format!("<{}> <{}> {object} .\n", triple.subject, triple.predicate)
        })
        .collect()
}

#[test]
fn profile_maps_deterministically_to_bounded_rdf_owl_prov_projection() {
    let visible = BTreeSet::from([
        "claim".to_string(),
        "supporting".to_string(),
        "contradicting".to_string(),
        "assessment".to_string(),
        "activity".to_string(),
        "agent".to_string(),
    ]);
    let first = build_export(&visible);
    let second = build_export(&visible);

    assert_eq!(first, second);
    assert_eq!(first.profile, "example.epistemic-replication");
    assert_eq!(first.profile_version, "1.0.0");
    assert_eq!(
        first
            .triples
            .iter()
            .filter(|triple| triple.predicate == RDF_TYPE && triple.object == iri(OWL_CLASS))
            .count(),
        8
    );
    assert!(first.triples.iter().any(|triple| {
        triple.predicate == PROV_DERIVED_FROM
            && triple.object == iri(instance_iri("claim-replication-001"))
    }));
    assert!(first.triples.iter().any(|triple| {
        triple.predicate == SEKAI_ASSERTION_MODE && triple.object == literal("derived")
    }));
    assert!(serde_json::to_vec(&first).unwrap().len() < MAX_SERIALIZED_BYTES);
    let ntriples = ntriples(&first);
    assert!(ntriples.contains(OWL_CLASS));
    assert!(ntriples.contains(PROV_DERIVED_FROM));
    assert!(ntriples.len() < MAX_SERIALIZED_BYTES);
    assert_eq!(first.losses, Vec::new());
}

#[test]
fn round_trip_preserves_identity_lifecycle_temporal_and_provenance_semantics() {
    let visible = BTreeSet::from([
        "claim".to_string(),
        "supporting".to_string(),
        "contradicting".to_string(),
        "assessment".to_string(),
        "activity".to_string(),
        "agent".to_string(),
    ]);
    let envelope = build_export(&visible);
    let imported = import_document(&envelope, &fixture_authorized_bindings())
        .expect("bounded projection should import");
    let profile = package();

    assert_eq!(imported.source_format, "rdf/owl/prov-o-canonical-triples");
    assert_eq!(imported.profile, "example.epistemic-replication");
    assert_eq!(imported.profile_version, "1.0.0");
    assert_eq!(
        imported.mapping_version,
        "sekai.epistemic-interoperability/v1"
    );
    assert_eq!(imported.namespace, "replication");
    assert_eq!(
        imported.confidence_basis,
        "bounded edge projection; no external inference"
    );
    assert_eq!(imported.profile_digest, digest(PROFILE_PACKAGE));
    assert_eq!(
        imported.receipt_digest,
        digest("receipt:replication-001:v1")
    );
    assert_eq!(
        imported.ontology_revision,
        profile_registry(&profile).revision()
    );
    assert_eq!(
        reconstructed_registry(&profile, &imported).revision(),
        imported.ontology_revision
    );
    let expected_classes = profile
        .classes
        .iter()
        .map(|class| class.name.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(imported.classes, expected_classes);
    assert_eq!(imported.relations.len(), 2);
    assert_eq!(
        imported.relations[&relation_iri("evidence_for")].domain,
        PROV_ENTITY
    );
    assert_eq!(
        imported.relations[&relation_iri("evidence_for")].range,
        class_iri("Claim")
    );
    assert_eq!(
        imported.relations[&relation_iri("derived_from")].range,
        PROV_ENTITY
    );

    let claim = instance_iri("claim-replication-001");
    let supporting = instance_iri("evidence-supporting");
    let contradicting = instance_iri("evidence-contradicting");
    let assessment = instance_iri("assessment-replication-001");
    let activity = instance_iri("activity-replication-evaluation");
    let agent = instance_iri("producer-replication-lab");
    assert_eq!(imported.assertion_modes[&claim], "asserted");
    assert_eq!(imported.lifecycle_statuses[&claim], "retracted");
    assert_eq!(imported.evidence_statuses[&claim], "contested");
    assert_eq!(imported.assertion_modes[&assessment], "derived");
    assert_eq!(imported.lifecycle_statuses[&assessment], "current");
    assert_eq!(imported.evidence_statuses[&assessment], "contested");
    assert_eq!(imported.evidence_statuses[&supporting], "supported");
    assert_eq!(imported.evidence_stances[&supporting], "supporting");
    assert_eq!(imported.evidence_statuses[&contradicting], "contested");
    assert_eq!(imported.evidence_stances[&contradicting], "contradicting");
    assert!(imported.provenance_types[&claim].contains(PROV_ENTITY));
    assert!(imported.provenance_types[&assessment].contains(PROV_ENTITY));
    assert!(imported.provenance_types[&activity].contains(PROV_ACTIVITY));
    assert!(imported.provenance_types[&agent].contains(PROV_AGENT));
    assert_eq!(imported.class_types[&claim], class_iri("Claim"));
    assert_eq!(imported.observed_at_unix_ms[&claim], 1_700_000_000_000);
    assert_eq!(imported.confidence_bases[&assessment], "producer_input");
    assert_eq!(imported.producer_confidence_bps[&assessment], 7000);
    assert_eq!(imported.properties.len(), 21);
    assert!(imported.properties.values().all(|property| {
        property.required && property.range == XSD_STRING && !property.domain.is_empty()
    }));
    assert_eq!(
        imported.source_digests[&claim],
        digest("claim:replication-001")
    );
    assert_eq!(
        imported.source_digests[&assessment],
        digest("assessment:replication-001:v1")
    );
    assert!(imported.evidence_edges.contains(&(
        instance_iri("evidence-supporting"),
        relation_iri("evidence_for"),
        claim.clone()
    )));
    assert!(imported.evidence_edges.contains(&(
        instance_iri("evidence-contradicting"),
        relation_iri("evidence_for"),
        claim.clone()
    )));
    assert!(imported.evidence_edges.contains(&(
        assessment.clone(),
        relation_iri("derived_from"),
        claim.clone()
    )));
    assert!(imported.provenance_edges.contains(&(
        assessment.clone(),
        PROV_DERIVED_FROM.into(),
        claim.clone()
    )));
    assert!(imported.losses.is_empty());
    assert!(imported.external_iris.is_empty());
}

#[test]
fn authorization_filters_hidden_identity_before_serialization() {
    let visible = authorized_names(&all_candidates(), "replication");
    let envelope = build_export(&visible);
    let serialized = serde_json::to_string(&envelope).unwrap();
    let hidden_digest = digest("evidence:contradicting:v1");

    assert!(visible.contains("claim"));
    assert!(visible.contains("supporting"));
    assert!(!visible.contains("contradicting"));
    assert!(!visible.contains("foreign-claim"));
    assert!(!serialized.contains(&hidden_digest));
    assert!(!serialized.contains("evidence-contradicting"));
    assert!(!envelope.references.contains_key("contradicting"));
    assert!(
        envelope
            .facts
            .iter()
            .all(|fact| fact.identity != instance_iri("evidence-contradicting"))
    );
    assert!(envelope.triples.iter().any(|triple| {
        triple.subject == instance_iri("claim-replication-001")
            && triple.predicate == SEKAI_LIFECYCLE_STATUS
            && triple.object == literal("retracted")
    }));

    let provenance_without_claim =
        BTreeSet::from(["assessment".to_string(), "activity".to_string()]);
    let provenance_export = build_export(&provenance_without_claim);
    assert!(provenance_export.triples.iter().any(|triple| {
        triple.subject == instance_iri("assessment-replication-001")
            && triple.predicate == PROV_GENERATED_BY
            && triple.object == iri(instance_iri("activity-replication-evaluation"))
    }));
    assert!(
        !provenance_export
            .triples
            .iter()
            .any(|triple| triple.predicate == PROV_DERIVED_FROM)
    );

    let hidden_target = BTreeSet::from(["supporting".to_string()]);
    let hidden_target_export = build_export(&hidden_target);
    let hidden_target_serialized = serde_json::to_string(&hidden_target_export).unwrap();
    assert!(!hidden_target_serialized.contains("instance/claim-replication-001"));
    assert!(
        !hidden_target_export
            .triples
            .iter()
            .any(|triple| triple.predicate == relation_iri("evidence_for"))
    );

    let independently_filtered = authorized_names(
        &[
            ExportCandidate {
                name: "claim",
                namespace: "replication",
                authorized: false,
                disclosed: true,
            },
            ExportCandidate {
                name: "supporting",
                namespace: "replication",
                authorized: true,
                disclosed: false,
            },
        ],
        "replication",
    );
    assert!(independently_filtered.is_empty());
    let independently_filtered_export = build_export(&independently_filtered);
    assert!(independently_filtered_export.facts.is_empty());
}

#[test]
fn unsupported_semantics_are_explicitly_lossy_and_bounded() {
    let visible = BTreeSet::from([
        "claim".to_string(),
        "supporting".to_string(),
        "assessment".to_string(),
        "activity".to_string(),
        "agent".to_string(),
    ]);
    let mut envelope = build_export(&visible);
    envelope.triples.push(triple(
        "https://foreign.example/ontology",
        OWL_IMPORTS,
        iri("https://foreign.example/ontology.owl"),
    ));
    envelope.triples.push(triple(
        instance_iri("claim-replication-001"),
        OWL_SAME_AS,
        iri("https://foreign.example/claim/1"),
    ));
    envelope
        .triples
        .push(triple(class_iri("Claim"), RDF_TYPE, iri(OWL_RESTRICTION)));
    envelope.triples.push(triple(
        class_iri("Replication"),
        RDFS_SUBCLASS,
        iri(class_iri("Claim")),
    ));
    envelope.triples.sort();

    let imported = import_document(&envelope, &fixture_authorized_bindings())
        .expect("unsupported terms remain bounded");
    let codes = imported
        .losses
        .iter()
        .map(|loss| loss.code.as_str())
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("unsupported_owl_imports"));
    assert!(codes.contains("identity_reconciliation_unsupported"));
    assert!(codes.contains("unsupported_owl_restriction"));
    assert!(codes.contains("unsupported_owl_entailment"));
    assert!(codes.contains("external_iri_not_reconciled"));
    assert!(
        imported
            .external_iris
            .contains("https://foreign.example/claim/1")
    );
    assert!(
        !imported
            .assertion_modes
            .contains_key("https://foreign.example/claim/1")
    );

    let mut literal_edge = build_export(&visible);
    literal_edge.triples.push(triple(
        instance_iri("evidence-supporting"),
        relation_iri("evidence_for").as_str(),
        literal("not-an-iri"),
    ));
    literal_edge.triples.sort();
    let literal_imported = import_document(&literal_edge, &fixture_authorized_bindings())
        .expect("literal edge is loss bounded");
    assert!(literal_imported.losses.iter().any(|loss| {
        loss.code == "unbound_edge_endpoint" && loss.term == relation_iri("evidence_for")
    }));

    let mut vocabulary_lookalike = build_export(&visible);
    vocabulary_lookalike.triples.push(triple(
        instance_iri("claim-replication-001"),
        PROV_DERIVED_FROM,
        iri("http://www.w3.org/ns/prov#attacker-object"),
    ));
    vocabulary_lookalike.triples.sort();
    let vocabulary_imported =
        import_document(&vocabulary_lookalike, &fixture_authorized_bindings())
            .expect("unknown vocabulary terms are lossy");
    assert!(vocabulary_imported.losses.iter().any(|loss| {
        loss.code == "external_iri_not_reconciled"
            && loss.term == "http://www.w3.org/ns/prov#attacker-object"
    }));
    assert!(
        !vocabulary_imported
            .provenance_edges
            .iter()
            .any(|edge| { edge.2 == "http://www.w3.org/ns/prov#attacker-object" })
    );

    let mut invalid_prov_edge = build_export(&visible);
    invalid_prov_edge.triples.push(triple(
        instance_iri("claim-replication-001"),
        PROV_USED,
        iri(instance_iri("evidence-supporting")),
    ));
    invalid_prov_edge.triples.sort();
    let invalid_prov_imported = import_document(&invalid_prov_edge, &fixture_authorized_bindings())
        .expect("invalid PROV edge is loss bounded");
    assert!(
        invalid_prov_imported
            .losses
            .iter()
            .any(|loss| loss.code == "prov_endpoint_type_mismatch")
    );
    assert!(
        !invalid_prov_imported
            .provenance_edges
            .iter()
            .any(|edge| { edge.0 == instance_iri("claim-replication-001") && edge.1 == PROV_USED })
    );

    let mut invalid_relation = build_export(&visible);
    invalid_relation.triples.push(triple(
        instance_iri("activity-replication-evaluation"),
        relation_iri("evidence_for").as_str(),
        iri(instance_iri("producer-replication-lab")),
    ));
    invalid_relation.triples.sort();
    let invalid_relation_imported =
        import_document(&invalid_relation, &fixture_authorized_bindings())
            .expect("invalid relation is loss bounded");
    assert!(
        invalid_relation_imported
            .losses
            .iter()
            .any(|loss| loss.code == "relation_endpoint_type_mismatch")
    );
    assert!(
        !invalid_relation_imported.evidence_edges.iter().any(|edge| {
            edge.0 == instance_iri("activity-replication-evaluation")
                && edge.1 == relation_iri("evidence_for")
        })
    );

    let mut invalid_derived_relation = build_export(&visible);
    invalid_derived_relation.triples.push(triple(
        instance_iri("activity-replication-evaluation"),
        relation_iri("derived_from").as_str(),
        iri(instance_iri("producer-replication-lab")),
    ));
    invalid_derived_relation.triples.sort();
    let invalid_derived_imported =
        import_document(&invalid_derived_relation, &fixture_authorized_bindings())
            .expect("invalid derived relation is loss bounded");
    let derived_loss = invalid_derived_imported
        .losses
        .iter()
        .find(|loss| {
            loss.code == "relation_endpoint_type_mismatch"
                && loss.term == relation_iri("derived_from")
        })
        .expect("derived relation endpoint mismatch is recorded");
    assert!(derived_loss.detail.contains("PROV Entity object"));

    let mut invalid_iri = build_export(&visible);
    invalid_iri
        .triples
        .iter_mut()
        .find(|triple| triple.object == iri(PROV_ENTITY))
        .expect("a PROV type object is present")
        .object = iri("https://example.invalid/unsafe\niri");
    invalid_iri.triples.sort();
    assert!(
        import_document(&invalid_iri, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("object is not a valid absolute IRI")
    );

    let mut multi_typed_agent = build_export(&visible);
    multi_typed_agent.triples.push(triple(
        instance_iri("producer-replication-lab"),
        RDF_TYPE,
        iri(PROV_ENTITY),
    ));
    multi_typed_agent.triples.sort();
    let multi_typed_imported = import_document(&multi_typed_agent, &fixture_authorized_bindings())
        .expect("multi-typed PROV resource remains valid");
    assert!(
        multi_typed_imported.provenance_types[&instance_iri("producer-replication-lab")]
            .contains(PROV_AGENT)
    );
    assert!(
        multi_typed_imported.provenance_types[&instance_iri("producer-replication-lab")]
            .contains(PROV_ENTITY)
    );

    let mut wrong_scalar_term = build_export(&visible);
    wrong_scalar_term
        .triples
        .iter_mut()
        .find(|triple| {
            triple.subject == instance_iri("claim-replication-001")
                && triple.predicate == SEKAI_ASSERTION_MODE
        })
        .expect("assertion metadata is present")
        .object = iri(PROV_ENTITY);
    wrong_scalar_term.triples.sort();
    assert!(
        import_document(&wrong_scalar_term, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("assertion mode must be a literal")
    );

    let mut vocabulary_metadata = build_export(&visible);
    vocabulary_metadata.triples.push(triple(
        class_iri("Claim"),
        SEKAI_ASSERTION_MODE,
        literal("asserted"),
    ));
    vocabulary_metadata.triples.sort();
    let vocabulary_metadata_imported =
        import_document(&vocabulary_metadata, &fixture_authorized_bindings())
            .expect("vocabulary metadata is loss bounded");
    assert!(
        vocabulary_metadata_imported
            .losses
            .iter()
            .any(|loss| loss.code == "metadata_subject_not_entity")
    );
    assert!(
        !vocabulary_metadata_imported
            .assertion_modes
            .contains_key(&class_iri("Claim"))
    );

    let mut tampered_property = build_export(&visible);
    let property_id = property_iri("Claim", "text");
    tampered_property
        .triples
        .iter_mut()
        .find(|triple| triple.subject == property_id && triple.predicate == SEKAI_REQUIRED)
        .expect("property required metadata is present")
        .object = literal("false");
    tampered_property.triples.sort();
    assert!(
        import_document(&tampered_property, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("property metadata")
    );

    let mut missing_property_type = build_export(&visible);
    let missing_property_id = property_iri("Claim", "text");
    missing_property_type.triples.retain(|triple| {
        !(triple.subject == missing_property_id
            && triple.predicate == RDF_TYPE
            && triple.object == iri(RDF_PROPERTY))
    });
    assert!(
        import_document(&missing_property_type, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("property rdf:type declarations")
    );

    let mut missing_fact = build_export(&visible);
    missing_fact
        .facts
        .retain(|fact| fact.identity != instance_iri("evidence-supporting"));
    assert!(
        import_document(&missing_fact, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("requires a fact record")
    );

    let mut invalid_confidence = build_export(&visible);
    invalid_confidence.confidence_basis.clear();
    assert!(
        import_document(&invalid_confidence, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("confidence basis")
    );

    let mut invalid_fact_digest = build_export(&visible);
    invalid_fact_digest
        .facts
        .iter_mut()
        .find(|fact| fact.identity == instance_iri("claim-replication-001"))
        .expect("claim fact is present")
        .source_digest = "x".into();
    assert!(
        import_document(&invalid_fact_digest, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("source digest")
    );

    let mut invalid_observation_time = build_export(&visible);
    invalid_observation_time
        .facts
        .iter_mut()
        .find(|fact| fact.identity == instance_iri("claim-replication-001"))
        .expect("claim fact is present")
        .observed_at_unix_ms = -1;
    assert!(
        import_document(&invalid_observation_time, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("observed time")
    );

    let mut conflicting_digest = build_export(&visible);
    conflicting_digest
        .facts
        .iter_mut()
        .find(|fact| fact.identity == instance_iri("claim-replication-001"))
        .expect("claim fact is present")
        .source_digest = digest("claim:swapped");
    assert!(
        import_document(&conflicting_digest, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("conflicting source digest")
    );

    let mut missing_binding = build_export(&visible);
    missing_binding.identity_bindings.clear();
    assert!(
        import_document(&missing_binding, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("identity binding required")
    );

    let mut unauthorized_binding = build_export(&visible);
    unauthorized_binding
        .identity_bindings
        .iter_mut()
        .find(|binding| binding.source_iri == instance_iri("claim-replication-001"))
        .expect("claim binding is present")
        .source_iri = "https://foreign.example/claim/1".into();
    unauthorized_binding.identity_bindings.sort();
    assert!(
        import_document(&unauthorized_binding, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("external resolution requires authenticated context")
    );

    let mut forged_binding = build_export(&visible);
    let forged_identity = instance_iri("attacker-controlled");
    let claim_binding = forged_binding
        .identity_bindings
        .iter_mut()
        .find(|binding| binding.source_iri == instance_iri("claim-replication-001"))
        .expect("claim binding is present");
    claim_binding.source_iri = forged_identity.clone();
    claim_binding.local_id = forged_identity;
    forged_binding.identity_bindings.sort();
    assert!(
        import_document(&forged_binding, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("not authorized by the import context")
    );

    let mut unsupported_version = build_export(&visible);
    unsupported_version.mapping_version = "sekai.epistemic-interoperability/v2".into();
    assert!(
        import_document(&unsupported_version, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("unsupported interop profile")
    );

    let mut unsupported_namespace = build_export(&visible);
    unsupported_namespace.namespace = "other-tenant".into();
    assert!(
        import_document(&unsupported_namespace, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("namespace is outside")
    );

    let mut mismatched_profile = build_export(&visible);
    mismatched_profile.profile_digest = digest("profile:other");
    mismatched_profile
        .references
        .insert("profile".into(), mismatched_profile.profile_digest.clone());
    assert!(
        import_document(&mismatched_profile, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("profile digest")
    );

    let mut conflicting_metadata = build_export(&visible);
    conflicting_metadata.triples.push(triple(
        instance_iri("claim-replication-001"),
        SEKAI_ASSERTION_MODE,
        literal("derived"),
    ));
    conflicting_metadata.triples.sort();
    assert!(
        import_document(&conflicting_metadata, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("conflicting assertion mode")
    );

    let mut blank_node = build_export(&visible);
    blank_node
        .triples
        .push(triple("_:b0", RDF_TYPE, iri(PROV_ENTITY)));
    blank_node.triples.sort();
    assert!(
        import_document(&blank_node, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("blank-node subject")
    );

    let mut oversized = build_export(&visible);
    oversized.triples.extend((0..MAX_TRIPLES).map(|index| {
        triple(
            format!("{BASE}instance/padding-{index}"),
            SEKAI_CONFIDENCE_BASIS,
            literal("padding"),
        )
    }));
    oversized.triples.sort();
    assert!(
        import_document(&oversized, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("exceeds bound")
    );

    let mut oversized_canonical = build_export(&visible);
    let oversized_literal = "x".repeat(MAX_IDENTIFIER_BYTES * 4);
    oversized_canonical.triples.extend((0..64).map(|index| {
        triple(
            format!("{BASE}instance/byte-padding-{index}"),
            SEKAI_CONFIDENCE_BASIS,
            literal(oversized_literal.clone()),
        )
    }));
    oversized_canonical.triples.sort();
    assert!(
        import_document(&oversized_canonical, &fixture_authorized_bindings())
            .unwrap_err()
            .contains("serialized envelope")
    );
}
