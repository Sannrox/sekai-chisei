//! External-adapter example for the fixed governed-fact profile.
//!
//! Two software concerns use the same domain-neutral Sekai structures. The
//! concern names and subject profiles belong to this adapter, not core Sekai.

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{KIND_EXTERNAL_EVIDENCE, Object};
use sekai_chisei::sekai::governed_facts::{
    FactApplicability, GovernedFactInput, GovernedFactType, PROFILE_CONTRACT_VERSION,
    VerificationContract, apply_profile, list_facts, put_fact, resolve_invariant_set,
};
use std::collections::HashMap;
use std::sync::Arc;

fn requirement(namespace: &str, id: &str, profile: &str, statement: &str) -> GovernedFactInput {
    GovernedFactInput {
        contract_version: PROFILE_CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        fact_id: id.into(),
        version: "1.0.0".into(),
        fact_type: GovernedFactType::Requirement,
        status: "active".into(),
        statement: statement.into(),
        applicability: FactApplicability {
            subject_profiles: vec![profile.into()],
            subject_refs: Vec::new(),
        },
        verification: VerificationContract::default(),
        requirement_version_ids: Vec::new(),
        evidence_refs: Vec::new(),
        source_ref: format!("adapter-policy:{id}"),
        effective_from_ms: 100,
        supersedes_object_id: String::new(),
        access_marking: String::new(),
    }
}

fn invariant(
    namespace: &str,
    id: &str,
    profile: &str,
    requirement_id: &str,
    evidence_id: &str,
) -> GovernedFactInput {
    GovernedFactInput {
        contract_version: PROFILE_CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        fact_id: id.into(),
        version: "1.0.0".into(),
        fact_type: GovernedFactType::Invariant,
        status: "active".into(),
        statement: "The admitted evidence satisfies this subject profile.".into(),
        applicability: FactApplicability {
            subject_profiles: vec![profile.into()],
            subject_refs: Vec::new(),
        },
        verification: VerificationContract {
            predicate_kind: "schema_conformance".into(),
            input_schema: "example.verification-input/v1".into(),
            result_schema: "example.verification-result/v1".into(),
            evidence_types: vec!["verification.result".into()],
        },
        requirement_version_ids: vec![requirement_id.into()],
        evidence_refs: vec![evidence_id.into()],
        source_ref: format!("adapter-policy:{id}"),
        effective_from_ms: 100,
        supersedes_object_id: String::new(),
        access_marking: String::new(),
    }
}

fn main() -> Result<(), String> {
    let namespace = "example-software";
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:")?));
    let profile = apply_profile(
        &db,
        namespace,
        PROFILE_CONTRACT_VERSION,
        "adapter:software",
        10,
    )?;
    let evidence_id = "example-verification-evidence";
    db.create_object_with_audit(
        &Object {
            id: evidence_id.into(),
            kind: KIND_EXTERNAL_EVIDENCE.into(),
            name: "synthetic adapter evidence".into(),
            namespace: namespace.into(),
            external_id: "adapter-evidence:synthetic".into(),
            properties: HashMap::new(),
            created: 20,
            updated: 20,
        },
        "adapter:software",
    )?;

    let api_requirement = put_fact(
        &db,
        requirement(
            namespace,
            "api-compatibility",
            "example.api-contract/v1",
            "The candidate preserves the declared API contract.",
        ),
        "adapter:software",
        100,
    )?;
    put_fact(
        &db,
        invariant(
            namespace,
            "api-schema-compatible",
            "example.api-contract/v1",
            &api_requirement.object_id,
            evidence_id,
        ),
        "adapter:software",
        101,
    )?;

    let migration_requirement = put_fact(
        &db,
        requirement(
            namespace,
            "migration-safety",
            "example.data-migration/v1",
            "The migration preserves recoverable stored data.",
        ),
        "adapter:software",
        102,
    )?;
    put_fact(
        &db,
        invariant(
            namespace,
            "migration-roundtrip-safe",
            "example.data-migration/v1",
            &migration_requirement.object_id,
            evidence_id,
        ),
        "adapter:software",
        103,
    )?;

    for (subject_profile, subject_ref) in [
        ("example.api-contract/v1", "release:candidate-1"),
        ("example.data-migration/v1", "migration:candidate-1"),
    ] {
        let resolved = resolve_invariant_set(
            &profile,
            list_facts(&db, namespace)?,
            Vec::new(),
            subject_profile,
            subject_ref,
            150,
            0,
        )?;
        println!(
            "{subject_profile}: {} requirement(s), {} invariant(s), {}",
            resolved.requirements.len(),
            resolved.invariants.len(),
            resolved.set_digest
        );
    }
    Ok(())
}
