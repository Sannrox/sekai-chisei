//! Versioned requirement, invariant, and waiver facts backed by the Sekai graph.
//!
//! The profile is intentionally closed and declarative. It stores immutable
//! documents as reserved graph objects so graph authorization, audit, backup,
//! and SQLite/PostgreSQL behavior remain authoritative without a parallel
//! requirements database.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{KIND_EXTERNAL_EVIDENCE, ListFilter, Object};
use crate::sekai::markings;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

pub const PROFILE_CONTRACT_VERSION: &str = "sekai.governed-facts/v1";
pub const PROFILE_KIND: &str = "governed_fact_profile";
pub const FACT_KIND: &str = "governed_fact_version";
pub const WAIVER_KIND: &str = "governed_waiver_version";
pub const MAX_FACTS_PER_NAMESPACE: usize = 1_000;
pub const MAX_REFERENCES_PER_FIELD: usize = 64;
pub const DEFAULT_RESOLUTION_LIMIT: usize = 128;
pub const MAX_RESOLUTION_LIMIT: usize = 256;

const DOCUMENT_PROPERTY: &str = "governed_document";
const CONTENT_DIGEST_PROPERTY: &str = "content_digest";
const CONTRACT_VERSION_PROPERTY: &str = "contract_version";
const EFFECTIVE_FROM_PROPERTY: &str = "effective_from_ms";
const EXPIRES_AT_PROPERTY: &str = "expires_at_ms";
const FACT_ID_PROPERTY: &str = "fact_id";
const FACT_TYPE_PROPERTY: &str = "fact_type";
const HISTORY_IDENTITY_PROPERTY: &str = "history_identity";
const SUPERSEDES_PROPERTY: &str = "supersedes_object_id";
const STATUS_PROPERTY: &str = "status";
const VERSION_PROPERTY: &str = "version";
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const MAX_STATEMENT_CHARS: usize = 16 * 1024;
const MAX_REASON_CHARS: usize = 4 * 1024;
const MAX_REFERENCE_CHARS: usize = 512;
const MAX_PROFILES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedFactType {
    Requirement,
    Invariant,
}

impl GovernedFactType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requirement => "requirement",
            Self::Invariant => "invariant",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "requirement" => Ok(Self::Requirement),
            "invariant" => Ok(Self::Invariant),
            _ => Err("fact_type must be requirement or invariant".into()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactApplicability {
    pub subject_profiles: Vec<String>,
    pub subject_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationContract {
    pub predicate_kind: String,
    pub input_schema: String,
    pub result_schema: String,
    pub evidence_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedFactInput {
    pub contract_version: String,
    pub namespace: String,
    pub fact_id: String,
    pub version: String,
    pub fact_type: GovernedFactType,
    pub status: String,
    pub statement: String,
    pub applicability: FactApplicability,
    pub verification: VerificationContract,
    pub requirement_version_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub source_ref: String,
    pub effective_from_ms: i64,
    pub supersedes_object_id: String,
    pub access_marking: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedFactVersion {
    pub object_id: String,
    pub content_digest: String,
    pub created_by: String,
    pub created_at_ms: i64,
    #[serde(flatten)]
    pub input: GovernedFactInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedWaiverInput {
    pub contract_version: String,
    pub namespace: String,
    pub waiver_id: String,
    pub version: String,
    pub invariant_version_ids: Vec<String>,
    pub applicability: FactApplicability,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub source_ref: String,
    pub valid_from_ms: i64,
    pub expires_at_ms: i64,
    pub supersedes_object_id: String,
    pub access_marking: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedWaiverVersion {
    pub object_id: String,
    pub content_digest: String,
    pub created_by: String,
    pub created_at_ms: i64,
    #[serde(flatten)]
    pub input: GovernedWaiverInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedFactProfile {
    pub object_id: String,
    pub contract_version: String,
    pub namespace: String,
    pub content_digest: String,
    pub applied_by: String,
    pub applied_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedInvariantSet {
    pub contract_version: String,
    pub set_id: String,
    pub set_digest: String,
    pub profile_digest: String,
    pub namespace: String,
    pub subject_profile: String,
    pub subject_ref: String,
    pub evaluation_time_ms: i64,
    pub requirements: Vec<GovernedFactVersion>,
    pub invariants: Vec<GovernedFactVersion>,
    pub waivers: Vec<GovernedWaiverVersion>,
}

#[derive(Serialize)]
struct CanonicalFact<'a> {
    input: &'a GovernedFactInput,
    created_by: &'a str,
}

#[derive(Serialize)]
struct CanonicalWaiver<'a> {
    input: &'a GovernedWaiverInput,
    created_by: &'a str,
}

pub fn profile_object_id(namespace: &str) -> String {
    digest_id(
        "governed-fact-profile",
        &[namespace, PROFILE_CONTRACT_VERSION],
    )
}

pub fn apply_profile(
    db: &RuntimeDb,
    namespace: &str,
    contract_version: &str,
    actor: &str,
    now_ms: i64,
) -> Result<GovernedFactProfile, String> {
    validate_namespace(namespace)?;
    validate_actor(actor)?;
    if contract_version != PROFILE_CONTRACT_VERSION {
        return Err("unsupported governed-fact profile version".into());
    }
    if now_ms <= 0 {
        return Err("profile application time must be positive".into());
    }
    let object_id = profile_object_id(namespace);
    let content_digest = profile_definition_digest()?;
    let profile = GovernedFactProfile {
        object_id: object_id.clone(),
        contract_version: PROFILE_CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        content_digest,
        applied_by: actor.into(),
        applied_at_ms: now_ms,
    };
    if let Some(existing) = db.get_object(&object_id)? {
        let existing = profile_from_object(&existing)?;
        if existing.contract_version == profile.contract_version
            && existing.namespace == profile.namespace
            && existing.content_digest == profile.content_digest
        {
            return Ok(existing);
        }
        return Err("governed-fact profile identity conflicts with existing content".into());
    }
    match db.create_object_with_audit(&profile_to_object(&profile), actor) {
        Ok(()) => Ok(profile),
        Err(error) => {
            let Some(existing) = db.get_object(&object_id)? else {
                return Err(error);
            };
            let existing = profile_from_object(&existing)?;
            if existing.contract_version == profile.contract_version
                && existing.namespace == profile.namespace
                && existing.content_digest == profile.content_digest
            {
                Ok(existing)
            } else {
                Err("governed-fact profile identity conflicts with existing content".into())
            }
        }
    }
}

pub fn put_fact(
    db: &RuntimeDb,
    input: GovernedFactInput,
    actor: &str,
    now_ms: i64,
) -> Result<GovernedFactVersion, String> {
    let input = normalize_fact(input)?;
    validate_actor(actor)?;
    ensure_profile(db, &input.namespace)?;
    let object_id = fact_object_id(
        &input.namespace,
        input.fact_type,
        &input.fact_id,
        &input.version,
    );
    let content_digest = digest_json(&CanonicalFact {
        input: &input,
        created_by: actor,
    })?;
    let fact = GovernedFactVersion {
        object_id: object_id.clone(),
        content_digest,
        created_by: actor.into(),
        created_at_ms: now_ms,
        input,
    };
    if let Some(existing) = db.get_object(&object_id)? {
        let existing = fact_from_object(&existing)?;
        if existing.content_digest == fact.content_digest {
            return Ok(existing);
        }
        return Err("governed fact version already exists with different content".into());
    }
    validate_fact_references(db, &fact.input)?;
    ensure_namespace_capacity(db, &fact.input.namespace, FACT_KIND)?;
    validate_fact_supersession(db, &fact)?;
    let history_identity = fact_history_identity(&fact.input);
    let object = fact_to_object(&fact)?;
    match db.create_governed_object_with_audit(
        &object,
        actor,
        HISTORY_IDENTITY_PROPERTY,
        &history_identity,
        SUPERSEDES_PROPERTY,
        &fact.input.supersedes_object_id,
        MAX_FACTS_PER_NAMESPACE,
    ) {
        Ok(()) => Ok(fact),
        Err(error) => replay_fact_after_create_conflict(db, &fact, error),
    }
}

pub fn put_waiver(
    db: &RuntimeDb,
    input: GovernedWaiverInput,
    actor: &str,
    now_ms: i64,
) -> Result<GovernedWaiverVersion, String> {
    let input = normalize_waiver(input)?;
    validate_actor(actor)?;
    ensure_profile(db, &input.namespace)?;
    let object_id = waiver_object_id(&input.namespace, &input.waiver_id, &input.version);
    let content_digest = digest_json(&CanonicalWaiver {
        input: &input,
        created_by: actor,
    })?;
    let waiver = GovernedWaiverVersion {
        object_id: object_id.clone(),
        content_digest,
        created_by: actor.into(),
        created_at_ms: now_ms,
        input,
    };
    if let Some(existing) = db.get_object(&object_id)? {
        let existing = waiver_from_object(&existing)?;
        if existing.content_digest == waiver.content_digest {
            return Ok(existing);
        }
        return Err("governed waiver version already exists with different content".into());
    }
    validate_waiver_references(db, &waiver.input)?;
    ensure_namespace_capacity(db, &waiver.input.namespace, WAIVER_KIND)?;
    validate_waiver_supersession(db, &waiver)?;
    let history_identity = waiver_history_identity(&waiver.input);
    let object = waiver_to_object(&waiver)?;
    match db.create_governed_object_with_audit(
        &object,
        actor,
        HISTORY_IDENTITY_PROPERTY,
        &history_identity,
        SUPERSEDES_PROPERTY,
        &waiver.input.supersedes_object_id,
        MAX_FACTS_PER_NAMESPACE,
    ) {
        Ok(()) => Ok(waiver),
        Err(error) => replay_waiver_after_create_conflict(db, &waiver, error),
    }
}

fn replay_fact_after_create_conflict(
    db: &RuntimeDb,
    fact: &GovernedFactVersion,
    create_error: String,
) -> Result<GovernedFactVersion, String> {
    let Some(existing) = db.get_object(&fact.object_id)? else {
        return Err(create_error);
    };
    let existing = fact_from_object(&existing)?;
    if existing.content_digest == fact.content_digest {
        Ok(existing)
    } else {
        Err("governed fact version already exists with different content".into())
    }
}

fn replay_waiver_after_create_conflict(
    db: &RuntimeDb,
    waiver: &GovernedWaiverVersion,
    create_error: String,
) -> Result<GovernedWaiverVersion, String> {
    let Some(existing) = db.get_object(&waiver.object_id)? else {
        return Err(create_error);
    };
    let existing = waiver_from_object(&existing)?;
    if existing.content_digest == waiver.content_digest {
        Ok(existing)
    } else {
        Err("governed waiver version already exists with different content".into())
    }
}

pub fn list_facts(db: &RuntimeDb, namespace: &str) -> Result<Vec<GovernedFactVersion>, String> {
    db.list_objects(&kind_filter(namespace, FACT_KIND))?
        .iter()
        .map(fact_from_object)
        .collect()
}

pub fn list_waivers(db: &RuntimeDb, namespace: &str) -> Result<Vec<GovernedWaiverVersion>, String> {
    db.list_objects(&kind_filter(namespace, WAIVER_KIND))?
        .iter()
        .map(waiver_from_object)
        .collect()
}

pub fn resolve_invariant_set(
    profile: &GovernedFactProfile,
    facts: Vec<GovernedFactVersion>,
    waivers: Vec<GovernedWaiverVersion>,
    subject_profile: &str,
    subject_ref: &str,
    evaluation_time_ms: i64,
    limit: usize,
) -> Result<ResolvedInvariantSet, String> {
    validate_reference("subject_profile", subject_profile)?;
    validate_reference("subject_ref", subject_ref)?;
    if evaluation_time_ms <= 0 {
        return Err("evaluation_time_ms must be positive".into());
    }
    let limit = if limit == 0 {
        DEFAULT_RESOLUTION_LIMIT
    } else {
        limit
    };
    if limit > MAX_RESOLUTION_LIMIT {
        return Err(format!(
            "invariant-set limit must not exceed {MAX_RESOLUTION_LIMIT}"
        ));
    }
    validate_fact_histories(
        facts
            .iter()
            .filter(|fact| fact.input.namespace == profile.namespace),
    )?;
    validate_waiver_histories(
        waivers
            .iter()
            .filter(|waiver| waiver.input.namespace == profile.namespace),
    )?;

    let superseded_facts = facts
        .iter()
        .filter(|fact| fact.input.effective_from_ms <= evaluation_time_ms)
        .filter_map(|fact| nonempty(&fact.input.supersedes_object_id).map(str::to_string))
        .collect::<BTreeSet<_>>();
    let mut applicable_facts = facts
        .into_iter()
        .filter(|fact| fact.input.namespace == profile.namespace)
        .filter(|fact| fact.input.effective_from_ms <= evaluation_time_ms)
        .filter(|fact| !superseded_facts.contains(fact.object_id.as_str()))
        .filter(|fact| fact.input.status == "active")
        .filter(|fact| applies(&fact.input.applicability, subject_profile, subject_ref))
        .collect::<Vec<_>>();
    applicable_facts.sort_by(|left, right| left.object_id.cmp(&right.object_id));
    let active_requirement_ids = applicable_facts
        .iter()
        .filter(|fact| fact.input.fact_type == GovernedFactType::Requirement)
        .map(|fact| fact.object_id.clone())
        .collect::<BTreeSet<_>>();
    applicable_facts.retain(|fact| {
        fact.input.fact_type == GovernedFactType::Requirement
            || fact
                .input
                .requirement_version_ids
                .iter()
                .all(|id| active_requirement_ids.contains(id.as_str()))
    });

    let active_invariant_ids = applicable_facts
        .iter()
        .filter(|fact| fact.input.fact_type == GovernedFactType::Invariant)
        .map(|fact| fact.object_id.as_str())
        .collect::<BTreeSet<_>>();
    let superseded_waivers = waivers
        .iter()
        .filter(|waiver| waiver.input.valid_from_ms <= evaluation_time_ms)
        .filter_map(|waiver| nonempty(&waiver.input.supersedes_object_id).map(str::to_string))
        .collect::<BTreeSet<_>>();
    let mut applicable_waivers = waivers
        .into_iter()
        .filter(|waiver| waiver.input.namespace == profile.namespace)
        .filter(|waiver| {
            waiver.input.valid_from_ms <= evaluation_time_ms
                && evaluation_time_ms < waiver.input.expires_at_ms
        })
        .filter(|waiver| !superseded_waivers.contains(waiver.object_id.as_str()))
        .filter(|waiver| applies(&waiver.input.applicability, subject_profile, subject_ref))
        .filter(|waiver| {
            waiver
                .input
                .invariant_version_ids
                .iter()
                .any(|id| active_invariant_ids.contains(id.as_str()))
        })
        .collect::<Vec<_>>();
    applicable_waivers.sort_by(|left, right| left.object_id.cmp(&right.object_id));

    if applicable_facts.len() + applicable_waivers.len() > limit {
        return Err("authorized invariant set exceeds the requested bound".into());
    }
    let (requirements, invariants): (Vec<_>, Vec<_>) = applicable_facts
        .into_iter()
        .partition(|fact| fact.input.fact_type == GovernedFactType::Requirement);
    let set_digest = digest_json(&serde_json::json!({
        "contract_version": PROFILE_CONTRACT_VERSION,
        "profile_digest": profile.content_digest,
        "namespace": profile.namespace,
        "subject_profile": subject_profile,
        "subject_ref": subject_ref,
        "evaluation_time_ms": evaluation_time_ms,
        "requirements": requirements.iter().map(|fact| (&fact.object_id, &fact.content_digest)).collect::<Vec<_>>(),
        "invariants": invariants.iter().map(|fact| (&fact.object_id, &fact.content_digest)).collect::<Vec<_>>(),
        "waivers": applicable_waivers.iter().map(|waiver| (&waiver.object_id, &waiver.content_digest)).collect::<Vec<_>>(),
    }))?;
    let set_id = format!(
        "invariant-set-{}",
        set_digest.strip_prefix("sha256:").unwrap_or(&set_digest)
    );
    Ok(ResolvedInvariantSet {
        contract_version: PROFILE_CONTRACT_VERSION.into(),
        set_id,
        set_digest,
        profile_digest: profile.content_digest.clone(),
        namespace: profile.namespace.clone(),
        subject_profile: subject_profile.into(),
        subject_ref: subject_ref.into(),
        evaluation_time_ms,
        requirements,
        invariants,
        waivers: applicable_waivers,
    })
}

pub fn profile_from_object(object: &Object) -> Result<GovernedFactProfile, String> {
    if object.kind != PROFILE_KIND {
        return Err("object is not a governed-fact profile".into());
    }
    let profile: GovernedFactProfile = parse_document(object)?;
    if profile.object_id != object.id
        || profile.namespace != object.namespace
        || profile.contract_version != PROFILE_CONTRACT_VERSION
        || profile.content_digest != profile_definition_digest()?
        || profile.content_digest
            != object
                .properties
                .get(CONTENT_DIGEST_PROPERTY)
                .cloned()
                .unwrap_or_default()
    {
        return Err("governed-fact profile integrity check failed".into());
    }
    Ok(profile)
}

fn profile_definition_digest() -> Result<String, String> {
    digest_json(&serde_json::json!({
        "contract_version": PROFILE_CONTRACT_VERSION,
        "fact_types": ["requirement", "invariant"],
        "waivers": true,
        "storage": "sekai_graph",
    }))
}

pub fn fact_from_object(object: &Object) -> Result<GovernedFactVersion, String> {
    if object.kind != FACT_KIND {
        return Err("object is not a governed fact version".into());
    }
    let fact: GovernedFactVersion = parse_document(object)?;
    if normalize_fact(fact.input.clone())? != fact.input {
        return Err("governed fact canonicalization check failed".into());
    }
    let expected_id = fact_object_id(
        &fact.input.namespace,
        fact.input.fact_type,
        &fact.input.fact_id,
        &fact.input.version,
    );
    let expected_digest = digest_json(&CanonicalFact {
        input: &fact.input,
        created_by: &fact.created_by,
    })?;
    if fact.object_id != object.id
        || fact.object_id != expected_id
        || fact.input.namespace != object.namespace
        || fact.created_at_ms != object.created
        || fact.content_digest != expected_digest
        || object.properties.get(CONTENT_DIGEST_PROPERTY) != Some(&fact.content_digest)
        || object.properties.get(HISTORY_IDENTITY_PROPERTY)
            != Some(&fact_history_identity(&fact.input))
        || object.properties.get(SUPERSEDES_PROPERTY) != Some(&fact.input.supersedes_object_id)
    {
        return Err("governed fact integrity check failed".into());
    }
    Ok(fact)
}

pub fn waiver_from_object(object: &Object) -> Result<GovernedWaiverVersion, String> {
    if object.kind != WAIVER_KIND {
        return Err("object is not a governed waiver version".into());
    }
    let waiver: GovernedWaiverVersion = parse_document(object)?;
    if normalize_waiver(waiver.input.clone())? != waiver.input {
        return Err("governed waiver canonicalization check failed".into());
    }
    let expected_id = waiver_object_id(
        &waiver.input.namespace,
        &waiver.input.waiver_id,
        &waiver.input.version,
    );
    let expected_digest = digest_json(&CanonicalWaiver {
        input: &waiver.input,
        created_by: &waiver.created_by,
    })?;
    if waiver.object_id != object.id
        || waiver.object_id != expected_id
        || waiver.input.namespace != object.namespace
        || waiver.created_at_ms != object.created
        || waiver.content_digest != expected_digest
        || object.properties.get(CONTENT_DIGEST_PROPERTY) != Some(&waiver.content_digest)
        || object.properties.get(HISTORY_IDENTITY_PROPERTY)
            != Some(&waiver_history_identity(&waiver.input))
        || object.properties.get(SUPERSEDES_PROPERTY) != Some(&waiver.input.supersedes_object_id)
    {
        return Err("governed waiver integrity check failed".into());
    }
    Ok(waiver)
}

fn normalize_fact(mut input: GovernedFactInput) -> Result<GovernedFactInput, String> {
    validate_common(
        &input.contract_version,
        &input.namespace,
        &input.fact_id,
        &input.version,
        input.effective_from_ms,
        &input.source_ref,
        &input.access_marking,
    )?;
    validate_bounded_text("statement", &input.statement, MAX_STATEMENT_CHARS)?;
    if !matches!(input.status.as_str(), "active" | "retired") {
        return Err("fact status must be active or retired".into());
    }
    normalize_applicability(&mut input.applicability)?;
    normalize_refs(
        "requirement_version_ids",
        &mut input.requirement_version_ids,
        MAX_REFERENCES_PER_FIELD,
    )?;
    normalize_refs(
        "evidence_refs",
        &mut input.evidence_refs,
        MAX_REFERENCES_PER_FIELD,
    )?;
    normalize_refs(
        "evidence_types",
        &mut input.verification.evidence_types,
        MAX_REFERENCES_PER_FIELD,
    )?;
    match input.fact_type {
        GovernedFactType::Requirement => {
            if input.verification != VerificationContract::default()
                || !input.requirement_version_ids.is_empty()
            {
                return Err(
                    "requirements cannot define invariant verification or requirement links".into(),
                );
            }
        }
        GovernedFactType::Invariant => {
            validate_identifier("predicate_kind", &input.verification.predicate_kind)?;
            validate_reference("input_schema", &input.verification.input_schema)?;
            validate_reference("result_schema", &input.verification.result_schema)?;
        }
    }
    validate_reference_or_empty("supersedes_object_id", &input.supersedes_object_id)?;
    ensure_document_bound(&input)?;
    Ok(input)
}

fn normalize_waiver(mut input: GovernedWaiverInput) -> Result<GovernedWaiverInput, String> {
    validate_common(
        &input.contract_version,
        &input.namespace,
        &input.waiver_id,
        &input.version,
        input.valid_from_ms,
        &input.source_ref,
        &input.access_marking,
    )?;
    if input.expires_at_ms <= input.valid_from_ms {
        return Err("waiver expiry must be after valid_from_ms".into());
    }
    validate_bounded_text("reason", &input.reason, MAX_REASON_CHARS)?;
    normalize_applicability(&mut input.applicability)?;
    normalize_refs(
        "invariant_version_ids",
        &mut input.invariant_version_ids,
        MAX_REFERENCES_PER_FIELD,
    )?;
    if input.invariant_version_ids.is_empty() {
        return Err("waiver must reference at least one invariant version".into());
    }
    normalize_refs(
        "evidence_refs",
        &mut input.evidence_refs,
        MAX_REFERENCES_PER_FIELD,
    )?;
    validate_reference_or_empty("supersedes_object_id", &input.supersedes_object_id)?;
    ensure_document_bound(&input)?;
    Ok(input)
}

fn validate_common(
    contract_version: &str,
    namespace: &str,
    logical_id: &str,
    version: &str,
    effective_from_ms: i64,
    source_ref: &str,
    access_marking: &str,
) -> Result<(), String> {
    if contract_version != PROFILE_CONTRACT_VERSION {
        return Err("unsupported governed-fact contract version".into());
    }
    validate_namespace(namespace)?;
    validate_identifier("logical identity", logical_id)?;
    validate_identifier("version", version)?;
    if effective_from_ms <= 0 {
        return Err("effective time must be positive".into());
    }
    validate_reference("source_ref", source_ref)?;
    markings::parse_optional_classification(access_marking)?;
    Ok(())
}

fn normalize_applicability(applicability: &mut FactApplicability) -> Result<(), String> {
    normalize_refs(
        "subject_profiles",
        &mut applicability.subject_profiles,
        MAX_PROFILES,
    )?;
    if applicability.subject_profiles.is_empty() {
        return Err("applicability requires at least one subject profile".into());
    }
    normalize_refs(
        "subject_refs",
        &mut applicability.subject_refs,
        MAX_REFERENCES_PER_FIELD,
    )
}

fn normalize_refs(field: &str, values: &mut Vec<String>, max: usize) -> Result<(), String> {
    if values.len() > max {
        return Err(format!("{field} exceeds the limit of {max}"));
    }
    for value in values.iter() {
        validate_reference(field, value)?;
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn validate_fact_references(db: &RuntimeDb, input: &GovernedFactInput) -> Result<(), String> {
    for requirement_id in &input.requirement_version_ids {
        let requirement = db
            .get_object(requirement_id)?
            .ok_or_else(|| "requirement version reference unavailable".to_string())?;
        let requirement = fact_from_object(&requirement)
            .map_err(|_| "requirement version reference unavailable".to_string())?;
        if requirement.input.namespace != input.namespace
            || requirement.input.fact_type != GovernedFactType::Requirement
        {
            return Err("requirement version reference unavailable".into());
        }
    }
    validate_evidence_references(db, &input.namespace, &input.evidence_refs)
}

fn validate_waiver_references(db: &RuntimeDb, input: &GovernedWaiverInput) -> Result<(), String> {
    for invariant_id in &input.invariant_version_ids {
        let invariant = db
            .get_object(invariant_id)?
            .ok_or_else(|| "invariant version reference unavailable".to_string())?;
        let invariant = fact_from_object(&invariant)
            .map_err(|_| "invariant version reference unavailable".to_string())?;
        if invariant.input.namespace != input.namespace
            || invariant.input.fact_type != GovernedFactType::Invariant
        {
            return Err("invariant version reference unavailable".into());
        }
    }
    validate_evidence_references(db, &input.namespace, &input.evidence_refs)
}

fn validate_evidence_references(
    db: &RuntimeDb,
    namespace: &str,
    evidence_refs: &[String],
) -> Result<(), String> {
    for evidence_ref in evidence_refs {
        let evidence = db
            .get_object(evidence_ref)?
            .ok_or_else(|| "evidence reference unavailable".to_string())?;
        if evidence.namespace != namespace || evidence.kind != KIND_EXTERNAL_EVIDENCE {
            return Err("evidence reference unavailable".into());
        }
    }
    Ok(())
}

fn validate_fact_supersession(db: &RuntimeDb, fact: &GovernedFactVersion) -> Result<(), String> {
    let existing = list_facts(db, &fact.input.namespace)?;
    let Some(superseded_id) = nonempty(&fact.input.supersedes_object_id) else {
        if existing.iter().any(|candidate| {
            candidate.input.fact_id == fact.input.fact_id
                && candidate.input.fact_type == fact.input.fact_type
        }) {
            return Err("new fact versions must supersede the exact current version".into());
        }
        return Ok(());
    };
    let superseded = db
        .get_object(superseded_id)?
        .ok_or_else(|| "superseded fact version unavailable".to_string())?;
    let superseded = fact_from_object(&superseded)
        .map_err(|_| "superseded fact version unavailable".to_string())?;
    if superseded.input.namespace != fact.input.namespace
        || superseded.input.fact_id != fact.input.fact_id
        || superseded.input.fact_type != fact.input.fact_type
        || superseded.input.version == fact.input.version
        || superseded.input.effective_from_ms > fact.input.effective_from_ms
    {
        return Err("superseded fact version is incompatible".into());
    }
    if existing
        .iter()
        .any(|candidate| candidate.input.supersedes_object_id == superseded_id)
    {
        return Err("fact version already has a superseding successor".into());
    }
    Ok(())
}

fn validate_waiver_supersession(
    db: &RuntimeDb,
    waiver: &GovernedWaiverVersion,
) -> Result<(), String> {
    let existing = list_waivers(db, &waiver.input.namespace)?;
    let Some(superseded_id) = nonempty(&waiver.input.supersedes_object_id) else {
        if existing
            .iter()
            .any(|candidate| candidate.input.waiver_id == waiver.input.waiver_id)
        {
            return Err("new waiver versions must supersede the exact current version".into());
        }
        return Ok(());
    };
    let superseded = db
        .get_object(superseded_id)?
        .ok_or_else(|| "superseded waiver version unavailable".to_string())?;
    let superseded = waiver_from_object(&superseded)
        .map_err(|_| "superseded waiver version unavailable".to_string())?;
    if superseded.input.namespace != waiver.input.namespace
        || superseded.input.waiver_id != waiver.input.waiver_id
        || superseded.input.version == waiver.input.version
        || superseded.input.valid_from_ms > waiver.input.valid_from_ms
    {
        return Err("superseded waiver version is incompatible".into());
    }
    if existing
        .iter()
        .any(|candidate| candidate.input.supersedes_object_id == superseded_id)
    {
        return Err("waiver version already has a superseding successor".into());
    }
    Ok(())
}

fn validate_fact_histories<'a>(
    facts: impl Iterator<Item = &'a GovernedFactVersion>,
) -> Result<(), String> {
    let facts = facts.collect::<Vec<_>>();
    let ids = facts
        .iter()
        .map(|fact| fact.object_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut successor_targets = BTreeSet::new();
    for fact in &facts {
        if let Some(target) = nonempty(&fact.input.supersedes_object_id)
            && (!ids.contains(target) || !successor_targets.insert(target))
        {
            return Err("governed fact history is ambiguous".into());
        }
    }
    for fact in &facts {
        let same_identity = facts
            .iter()
            .filter(|candidate| {
                candidate.input.fact_id == fact.input.fact_id
                    && candidate.input.fact_type == fact.input.fact_type
            })
            .collect::<Vec<_>>();
        if same_identity.len() <= 1 {
            continue;
        }
        let roots = same_identity
            .iter()
            .filter(|candidate| candidate.input.supersedes_object_id.is_empty())
            .count();
        let leaves = same_identity
            .iter()
            .filter(|candidate| !successor_targets.contains(candidate.object_id.as_str()))
            .count();
        if roots != 1 || leaves != 1 {
            return Err("governed fact history is ambiguous".into());
        }
    }
    Ok(())
}

fn validate_waiver_histories<'a>(
    waivers: impl Iterator<Item = &'a GovernedWaiverVersion>,
) -> Result<(), String> {
    let waivers = waivers.collect::<Vec<_>>();
    let ids = waivers
        .iter()
        .map(|waiver| waiver.object_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut successor_targets = BTreeSet::new();
    for waiver in &waivers {
        if let Some(target) = nonempty(&waiver.input.supersedes_object_id)
            && (!ids.contains(target) || !successor_targets.insert(target))
        {
            return Err("governed waiver history is ambiguous".into());
        }
    }
    for waiver in &waivers {
        let same_identity = waivers
            .iter()
            .filter(|candidate| candidate.input.waiver_id == waiver.input.waiver_id)
            .collect::<Vec<_>>();
        if same_identity.len() <= 1 {
            continue;
        }
        let roots = same_identity
            .iter()
            .filter(|candidate| candidate.input.supersedes_object_id.is_empty())
            .count();
        let leaves = same_identity
            .iter()
            .filter(|candidate| !successor_targets.contains(candidate.object_id.as_str()))
            .count();
        if roots != 1 || leaves != 1 {
            return Err("governed waiver history is ambiguous".into());
        }
    }
    Ok(())
}

fn ensure_profile(db: &RuntimeDb, namespace: &str) -> Result<(), String> {
    let profile = db
        .get_object(&profile_object_id(namespace))?
        .ok_or_else(|| "governed-fact profile is not applied".to_string())?;
    profile_from_object(&profile)?;
    Ok(())
}

fn ensure_namespace_capacity(db: &RuntimeDb, namespace: &str, kind: &str) -> Result<(), String> {
    if db.list_objects(&kind_filter(namespace, kind))?.len() >= MAX_FACTS_PER_NAMESPACE {
        return Err("governed-fact namespace capacity exhausted".into());
    }
    Ok(())
}

fn profile_to_object(profile: &GovernedFactProfile) -> Object {
    Object {
        id: profile.object_id.clone(),
        kind: PROFILE_KIND.into(),
        name: PROFILE_CONTRACT_VERSION.into(),
        namespace: profile.namespace.clone(),
        external_id: format!(
            "governed-fact-profile:{}:{}",
            profile.namespace, PROFILE_CONTRACT_VERSION
        ),
        properties: HashMap::from([
            (
                CONTRACT_VERSION_PROPERTY.into(),
                profile.contract_version.clone(),
            ),
            (
                CONTENT_DIGEST_PROPERTY.into(),
                profile.content_digest.clone(),
            ),
            (
                DOCUMENT_PROPERTY.into(),
                serde_json::to_string(profile).expect("profile is serializable"),
            ),
        ]),
        created: profile.applied_at_ms,
        updated: profile.applied_at_ms,
    }
}

fn fact_to_object(fact: &GovernedFactVersion) -> Result<Object, String> {
    let history_identity = fact_history_identity(&fact.input);
    let mut properties = HashMap::from([
        (
            CONTRACT_VERSION_PROPERTY.into(),
            fact.input.contract_version.clone(),
        ),
        (FACT_ID_PROPERTY.into(), fact.input.fact_id.clone()),
        (
            FACT_TYPE_PROPERTY.into(),
            fact.input.fact_type.as_str().into(),
        ),
        (HISTORY_IDENTITY_PROPERTY.into(), history_identity),
        (STATUS_PROPERTY.into(), fact.input.status.clone()),
        (VERSION_PROPERTY.into(), fact.input.version.clone()),
        (
            EFFECTIVE_FROM_PROPERTY.into(),
            fact.input.effective_from_ms.to_string(),
        ),
        (
            SUPERSEDES_PROPERTY.into(),
            fact.input.supersedes_object_id.clone(),
        ),
        (CONTENT_DIGEST_PROPERTY.into(), fact.content_digest.clone()),
        (
            DOCUMENT_PROPERTY.into(),
            serde_json::to_string(fact).map_err(err)?,
        ),
    ]);
    if !fact.input.access_marking.is_empty() {
        properties.insert(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            fact.input.access_marking.clone(),
        );
    }
    Ok(Object {
        id: fact.object_id.clone(),
        kind: FACT_KIND.into(),
        name: format!("{}@{}", fact.input.fact_id, fact.input.version),
        namespace: fact.input.namespace.clone(),
        external_id: format!(
            "governed-fact:{}:{}:{}",
            fact.input.fact_type.as_str(),
            fact.input.fact_id,
            fact.input.version
        ),
        properties,
        created: fact.created_at_ms,
        updated: fact.created_at_ms,
    })
}

fn waiver_to_object(waiver: &GovernedWaiverVersion) -> Result<Object, String> {
    let history_identity = waiver_history_identity(&waiver.input);
    let mut properties = HashMap::from([
        (
            CONTRACT_VERSION_PROPERTY.into(),
            waiver.input.contract_version.clone(),
        ),
        (FACT_ID_PROPERTY.into(), waiver.input.waiver_id.clone()),
        (HISTORY_IDENTITY_PROPERTY.into(), history_identity),
        (VERSION_PROPERTY.into(), waiver.input.version.clone()),
        (
            EFFECTIVE_FROM_PROPERTY.into(),
            waiver.input.valid_from_ms.to_string(),
        ),
        (
            EXPIRES_AT_PROPERTY.into(),
            waiver.input.expires_at_ms.to_string(),
        ),
        (
            SUPERSEDES_PROPERTY.into(),
            waiver.input.supersedes_object_id.clone(),
        ),
        (
            CONTENT_DIGEST_PROPERTY.into(),
            waiver.content_digest.clone(),
        ),
        (
            DOCUMENT_PROPERTY.into(),
            serde_json::to_string(waiver).map_err(err)?,
        ),
    ]);
    if !waiver.input.access_marking.is_empty() {
        properties.insert(
            markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
            waiver.input.access_marking.clone(),
        );
    }
    Ok(Object {
        id: waiver.object_id.clone(),
        kind: WAIVER_KIND.into(),
        name: format!("{}@{}", waiver.input.waiver_id, waiver.input.version),
        namespace: waiver.input.namespace.clone(),
        external_id: format!(
            "governed-waiver:{}:{}",
            waiver.input.waiver_id, waiver.input.version
        ),
        properties,
        created: waiver.created_at_ms,
        updated: waiver.created_at_ms,
    })
}

fn fact_history_identity(input: &GovernedFactInput) -> String {
    format!("{}:{}", input.fact_type.as_str(), input.fact_id)
}

fn waiver_history_identity(input: &GovernedWaiverInput) -> String {
    format!("waiver:{}", input.waiver_id)
}

fn parse_document<T: for<'de> Deserialize<'de>>(object: &Object) -> Result<T, String> {
    let document = object
        .properties
        .get(DOCUMENT_PROPERTY)
        .ok_or_else(|| "governed document is unavailable".to_string())?;
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err("governed document exceeds its stored bound".into());
    }
    serde_json::from_str(document).map_err(|_| "governed document is invalid".into())
}

pub fn fact_object_id(
    namespace: &str,
    fact_type: GovernedFactType,
    fact_id: &str,
    version: &str,
) -> String {
    digest_id(
        "governed-fact",
        &[namespace, fact_type.as_str(), fact_id, version],
    )
}

pub fn waiver_object_id(namespace: &str, waiver_id: &str, version: &str) -> String {
    digest_id("governed-waiver", &[namespace, waiver_id, version])
}

fn digest_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update([0]);
        hasher.update(part.as_bytes());
    }
    format!("{prefix}-{:x}", hasher.finalize())
}

fn digest_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(err)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn ensure_document_bound(value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(err)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "governed document exceeds {MAX_DOCUMENT_BYTES} bytes"
        ));
    }
    Ok(())
}

fn kind_filter(namespace: &str, kind: &str) -> ListFilter {
    ListFilter {
        kind: Some(kind.into()),
        namespace: Some(namespace.into()),
        limit: MAX_FACTS_PER_NAMESPACE as i32,
        ..ListFilter::default()
    }
}

fn applies(applicability: &FactApplicability, subject_profile: &str, subject_ref: &str) -> bool {
    applicability
        .subject_profiles
        .binary_search_by(|candidate| candidate.as_str().cmp(subject_profile))
        .is_ok()
        && (applicability.subject_refs.is_empty()
            || applicability
                .subject_refs
                .binary_search_by(|candidate| candidate.as_str().cmp(subject_ref))
                .is_ok())
}

fn validate_namespace(namespace: &str) -> Result<(), String> {
    validate_reference("namespace", namespace)
}

fn validate_actor(actor: &str) -> Result<(), String> {
    validate_reference("authenticated actor", actor)
}

fn validate_identifier(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("{field} must be a bounded identifier"));
    }
    Ok(())
}

fn validate_reference(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_REFERENCE_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(format!("{field} must be a non-empty bounded reference"));
    }
    Ok(())
}

fn validate_reference_or_empty(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Ok(())
    } else {
        validate_reference(field, value)
    }
}

fn validate_bounded_text(field: &str, value: &str, max_chars: usize) -> Result<(), String> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > max_chars
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(format!("{field} must be non-empty and bounded"));
    }
    Ok(())
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use std::sync::{Arc, Barrier};

    fn applicability(profile: &str) -> FactApplicability {
        FactApplicability {
            subject_profiles: vec![profile.into()],
            subject_refs: Vec::new(),
        }
    }

    fn requirement(namespace: &str, fact_id: &str) -> GovernedFactInput {
        GovernedFactInput {
            contract_version: PROFILE_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            fact_id: fact_id.into(),
            version: "1.0.0".into(),
            fact_type: GovernedFactType::Requirement,
            status: "active".into(),
            statement: "The subject preserves its declared compatibility contract.".into(),
            applicability: applicability("example.subject/v1"),
            verification: VerificationContract::default(),
            requirement_version_ids: Vec::new(),
            evidence_refs: Vec::new(),
            source_ref: "policy:compatibility".into(),
            effective_from_ms: 10,
            supersedes_object_id: String::new(),
            access_marking: String::new(),
        }
    }

    #[test]
    fn immutable_versions_and_historical_resolution_survive_supersession() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        let profile = apply_profile(&db, "acme", PROFILE_CONTRACT_VERSION, "local", 1).unwrap();
        let v1 = put_fact(&db, requirement("acme", "compatibility"), "local", 10).unwrap();
        let mut v2_input = requirement("acme", "compatibility");
        v2_input.version = "2.0.0".into();
        v2_input.statement = "The subject preserves compatibility and migration safety.".into();
        v2_input.effective_from_ms = 20;
        v2_input.supersedes_object_id = v1.object_id.clone();
        let v2 = put_fact(&db, v2_input, "local", 20).unwrap();

        let at_15 = resolve_invariant_set(
            &profile,
            list_facts(&db, "acme").unwrap(),
            Vec::new(),
            "example.subject/v1",
            "subject:one",
            15,
            0,
        )
        .unwrap();
        assert_eq!(at_15.requirements[0].object_id, v1.object_id);
        let at_25 = resolve_invariant_set(
            &profile,
            list_facts(&db, "acme").unwrap(),
            Vec::new(),
            "example.subject/v1",
            "subject:one",
            25,
            0,
        )
        .unwrap();
        assert_eq!(at_25.requirements[0].object_id, v2.object_id);
        assert!(db.get_object(&v1.object_id).unwrap().is_some());

        let mut retired = requirement("acme", "compatibility");
        retired.version = "3.0.0".into();
        retired.status = "retired".into();
        retired.effective_from_ms = 30;
        retired.supersedes_object_id = v2.object_id;
        put_fact(&db, retired, "local", 30).unwrap();
        let at_35 = resolve_invariant_set(
            &profile,
            list_facts(&db, "acme").unwrap(),
            Vec::new(),
            "example.subject/v1",
            "subject:one",
            35,
            0,
        )
        .unwrap();
        assert!(at_35.requirements.is_empty());
    }

    #[test]
    fn conflicting_replay_and_supersession_forks_fail_closed() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        apply_profile(&db, "acme", PROFILE_CONTRACT_VERSION, "local", 1).unwrap();
        let v1 = put_fact(&db, requirement("acme", "compatibility"), "local", 10).unwrap();
        assert_eq!(
            put_fact(&db, requirement("acme", "compatibility"), "local", 11)
                .unwrap()
                .object_id,
            v1.object_id
        );
        let mut conflict = requirement("acme", "compatibility");
        conflict.statement = "Different content.".into();
        assert!(put_fact(&db, conflict, "local", 12).is_err());

        let mut missing_predecessor = requirement("acme", "compatibility");
        missing_predecessor.version = "2.0.0".into();
        missing_predecessor.effective_from_ms = 20;
        assert!(put_fact(&db, missing_predecessor, "local", 20).is_err());

        let mut invalid_status = requirement("acme", "another-requirement");
        invalid_status.status = "draft".into();
        assert!(put_fact(&db, invalid_status, "local", 12).is_err());

        let mut v2 = requirement("acme", "compatibility");
        v2.version = "2.0.0".into();
        v2.effective_from_ms = 20;
        v2.supersedes_object_id = v1.object_id.clone();
        put_fact(&db, v2, "local", 20).unwrap();
        let mut fork = requirement("acme", "compatibility");
        fork.version = "3.0.0".into();
        fork.effective_from_ms = 30;
        fork.supersedes_object_id = v1.object_id;
        assert!(put_fact(&db, fork, "local", 30).is_err());
    }

    #[test]
    fn concurrent_profile_and_successor_writes_converge_without_a_fork() {
        let path = std::env::temp_dir().join(format!(
            "sekai-governed-fact-race-{}.db",
            uuid::Uuid::new_v4().simple()
        ));
        let namespace = format!("race-{}", uuid::Uuid::new_v4().simple());
        let db_a = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap()));
        let db_b = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap()));
        let barrier = Arc::new(Barrier::new(2));
        let profile_threads = [
            (db_a.clone(), barrier.clone(), namespace.clone()),
            (db_b.clone(), barrier.clone(), namespace.clone()),
        ]
        .map(|(db, barrier, namespace)| {
            std::thread::spawn(move || {
                barrier.wait();
                apply_profile(&db, &namespace, PROFILE_CONTRACT_VERSION, "local", 1)
            })
        });
        let profiles = profile_threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(profiles[0].object_id, profiles[1].object_id);

        let v1 = put_fact(&db_a, requirement(&namespace, "compatibility"), "local", 10).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let successor_threads = [
            (
                db_a.clone(),
                barrier.clone(),
                namespace.clone(),
                v1.object_id.clone(),
                "2.0.0",
            ),
            (
                db_b.clone(),
                barrier.clone(),
                namespace.clone(),
                v1.object_id,
                "3.0.0",
            ),
        ]
        .map(|(db, barrier, namespace, predecessor, version)| {
            std::thread::spawn(move || {
                let mut successor = requirement(&namespace, "compatibility");
                successor.version = version.into();
                successor.effective_from_ms = 20;
                successor.supersedes_object_id = predecessor;
                barrier.wait();
                put_fact(&db, successor, "local", 20)
            })
        });
        let outcomes = successor_threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );
        let facts = list_facts(&db_a, &namespace).unwrap();
        assert_eq!(facts.len(), 2);
        assert!(
            resolve_invariant_set(
                &profiles[0],
                facts,
                Vec::new(),
                "example.subject/v1",
                "subject:one",
                25,
                0,
            )
            .is_ok()
        );
    }
}
